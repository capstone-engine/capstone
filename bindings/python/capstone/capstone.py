# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import arm, arm64, mips, x86

__all__ = [
    'cs',
    'cs_insn',
    'cs_disasm_quick',
    'cs_version',
    'CS_ARCH_ARM',
    'CS_ARCH_ARM64',
    'CS_ARCH_MIPS',
    'CS_ARCH_X86',

    'CS_MODE_LITTLE_ENDIAN',
    'CS_MODE_BIG_ENDIAN',
    'CS_MODE_SYNTAX_INTEL',
    'CS_MODE_SYNTAX_ATT',
    'CS_MODE_16',
    'CS_MODE_32',
    'CS_MODE_64',
    'CS_MODE_ARM',
    'CS_MODE_THUMB',
    'CS_MODE_MICRO',
    'CS_MODE_N64',

    'CS_ERR_OK',
    'CS_ERR_MEM',
    'CS_ERR_ARCH',
    'CS_ERR_HANDLE',
    'CS_ERR_CSH',
    'CS_ERR_MODE',
]

# capstone C interface
# architectures
CS_ARCH_ARM = 0
CS_ARCH_ARM64 = 1
CS_ARCH_MIPS = 2
CS_ARCH_X86 = 3

# disasm mode
CS_MODE_LITTLE_ENDIAN = 0      # little-endian mode (default mode)
CS_MODE_SYNTAX_INTEL = 0       # Intel X86 asm syntax (default for CS_ARCH_X86)
CS_MODE_ARM = 0                # ARM mode
CS_MODE_16 = (1 << 1)          # 16-bit mode (for X86, Mips)
CS_MODE_32 = (1 << 2)          # 32-bit mode (for X86, Mips)
CS_MODE_64 = (1 << 3)          # 64-bit mode (for X86, Mips)
CS_MODE_THUMB = (1 << 4)       # ARM's Thumb mode, including Thumb-2
CS_MODE_MICRO = (1 << 4),      # MicroMips mode (MIPS architecture)
CS_MODE_N64 = (1 << 5),        # Nintendo-64 mode (MIPS architecture)
CS_MODE_SYNTAX_ATT = (1 << 30) # X86 ATT asm syntax (for CS_ARCH_X86 only)
CS_MODE_BIG_ENDIAN = (1 << 31) # big-endian mode

# capstone error type
CS_ERR_OK = 0      # No error: everything was fine
CS_ERR_MEM = 1     # Out-Of-Memory error
CS_ERR_ARCH = 2    # Unsupported architecture
CS_ERR_HANDLE = 3  # Invalid handle
CS_ERR_CSH = 4     # Invalid csh argument
CS_ERR_MODE = 5    # Invalid/unsupported mode


import ctypes, ctypes.util
from os.path import split, join
import distutils.sysconfig


# load all the libs
_lib_path = split(__file__)[0]
_all_libs = ['capstone.dll', 'libcapstone.so', 'libcapstone.dylib']
_found = False

for _lib in _all_libs:
    try:
        _lib_file = join(_lib_path, _lib)
        # print "Trying to load:", _lib_file
        _cs = ctypes.cdll.LoadLibrary(_lib_file)
        _found = True
        break
    except OSError:
        pass
if _found == False:
    # try loading from default paths
    for _lib in _all_libs:
        try:
            _cs = ctypes.cdll.LoadLibrary(_lib)
            _found = True
            break
        except OSError:
            pass

if _found == False:
    # last try: loading from python lib directory
    _lib_path = distutils.sysconfig.get_python_lib()
    for _lib in _all_libs:
        try:
            _lib_file = join(_lib_path, 'capstone', _lib)
            # print "Trying to load:", _lib_file
            _cs = ctypes.cdll.LoadLibrary(_lib_file)
            _found = True
            break
        except OSError:
            pass
    if _found == False:
        raise ImportError("ERROR: fail to load the dynamic library.")


class _cs_arch(ctypes.Union):
    _fields_ = (
        ('arm64', arm64._cs_arm64),
        ('arm', arm._cs_arm),
        ('mips', mips._cs_mips),
        ('x86', x86._cs_x86),
    )

# low-level structure for C code
class _cs_insn(ctypes.Structure):
    _fields_ = (
        ('id', ctypes.c_uint),
        ('address', ctypes.c_size_t),
        ('size', ctypes.c_uint16),
        ('mnemonic', ctypes.c_char * 32),
        ('op_str', ctypes.c_char * 96),
        ('regs_read', ctypes.c_uint * 32),
        ('regs_write', ctypes.c_uint * 32),
        ('groups', ctypes.c_uint * 8),
        ('arch', _cs_arch),
    )

# setup all the function prototype
def _setup_prototype(lib, fname, restype, *argtypes):
    getattr(lib, fname).restype = restype
    getattr(lib, fname).argtypes = argtypes

_setup_prototype(_cs, "cs_open", ctypes.c_int, ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(ctypes.c_uint64))
_setup_prototype(_cs, "cs_disasm_dyn", ctypes.c_size_t, ctypes.c_size_t, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t, \
        ctypes.c_size_t, ctypes.c_size_t, ctypes.POINTER(ctypes.POINTER(_cs_insn)))
_setup_prototype(_cs, "cs_free", None, ctypes.c_void_p)
_setup_prototype(_cs, "cs_close", ctypes.c_int, ctypes.POINTER(ctypes.c_uint64))
_setup_prototype(_cs, "cs_reg_name", ctypes.c_char_p, ctypes.c_uint64, ctypes.c_uint)
_setup_prototype(_cs, "cs_insn_name", ctypes.c_char_p, ctypes.c_uint64, ctypes.c_uint)
_setup_prototype(_cs, "cs_insn_group", ctypes.c_bool, ctypes.c_uint64, ctypes.POINTER(_cs_insn), ctypes.c_uint)
_setup_prototype(_cs, "cs_reg_read", ctypes.c_bool, ctypes.c_uint64, ctypes.POINTER(_cs_insn), ctypes.c_uint)
_setup_prototype(_cs, "cs_reg_write", ctypes.c_bool, ctypes.c_uint64, ctypes.POINTER(_cs_insn), ctypes.c_uint)
_setup_prototype(_cs, "cs_op_count", ctypes.c_int, ctypes.c_uint64, ctypes.POINTER(_cs_insn), ctypes.c_uint)
_setup_prototype(_cs, "cs_op_index", ctypes.c_int, ctypes.c_uint64, ctypes.POINTER(_cs_insn), ctypes.c_uint, ctypes.c_uint)
_setup_prototype(_cs, "cs_version", None, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
_setup_prototype(_cs, "cs_errno", ctypes.c_int, ctypes.c_int64)


def cs_version():
    major = ctypes.c_int()
    minor = ctypes.c_int()
    _cs.cs_version(ctypes.byref(major), ctypes.byref(minor))
    return (major.value, minor.value)


# quick & dirty Python function to disasm raw binary code
def cs_disasm_quick(arch, mode, code, offset, count = 0):
    csh = ctypes.c_uint64()
    status = _cs.cs_open(arch, mode, ctypes.byref(csh))
    if status != CS_ERR_OK:
        return
    all_insn = ctypes.POINTER(_cs_insn)()
    res = _cs.cs_disasm_dyn(csh, code, len(code), offset, count, ctypes.byref(all_insn))
    if res > 0:
        for i in xrange(res):
            yield all_insn[i]
    else:
        yield []

        _cs.cs_free(all_insn)
    _cs.cs_close(csh)


# Python-style class to disasm code
class cs_insn:
    def __init__(self, csh, all_info, arch):
        def create_list(rawlist):
            fl = []
            for m in rawlist:
                if m == 0:
                    break
                fl.append(m)
            return fl

        self.id = all_info.id
        self.address = all_info.address
        self.size = all_info.size
        self.mnemonic = all_info.mnemonic
        self.op_str = all_info.op_str
        self.regs_read = create_list(all_info.regs_read)
        self.regs_write = create_list(all_info.regs_write)
        self.groups = create_list(all_info.groups)

        if arch == CS_ARCH_ARM:
            (self.cc, self.update_flags, self.writeback, self.operands) = \
                arm.get_arch_info(all_info.arch.arm)
        elif arch == CS_ARCH_ARM64:
            (self.cc, self.update_flags, self.writeback, self.operands) = \
                arm64.get_arch_info(all_info.arch.arm64)
        elif arch == CS_ARCH_X86:
            (self.prefix, self.segment, self.opcode, self.op_size, self.addr_size, \
             self.disp_size, self.imm_size, self.modrm, self.sib, self.disp, \
             self.sib_index, self.sib_scale, self.sib_base, self.operands) = x86.get_arch_info(all_info.arch.x86)
        elif arch == CS_ARCH_MIPS:
             self.operands = mips.get_arch_info(all_info.arch.mips)

        # save original insn for later use
        self.raw_insn = all_info
        self.csh = csh


    def errno():
        return _cs.cs_errno(self.csh)

    def reg_name(self, reg_id):
        if self.csh is None:
            raise ValueError("Error: Failed to initialize!")
        return _cs.cs_reg_name(self.csh, reg_id)

    def insn_name(self):
        if self.csh is None:
            raise ValueError("Error: Failed to initialize!")
        return _cs.cs_insn_name(self.csh, self.id)

    def group(self, group_id):
        if self.csh is None:
            raise ValueError("Error: Failed to initialize!")
        return _cs.cs_insn_group(self.csh, self.raw_insn, group_id)

    def reg_read(self, reg_id):
        if self.csh is None:
            raise ValueError("Error: Failed to initialize!")
        return _cs.cs_reg_read(self.csh, self.raw_insn, reg_id)

    def reg_write(self, reg_id):
        if self.csh is None:
            raise ValueError("Error: Failed to initialize!")
        return _cs.cs_reg_write(self.csh, self.raw_insn, reg_id)

    def op_count(self, op_type):
        if self.csh is None:
            raise ValueError("Error: Failed to initialize!")
        return _cs.cs_op_count(self.csh, self.raw_insn, op_type)

    def op_index(self, op_type, position):
        if self.csh is None:
            raise ValueError("Error: Failed to initialize!")
        return _cs.cs_op_index(self.csh, self.raw_insn, op_type, position)


class cs:
    def __init__(self, arch, mode):
        self.arch, self.mode = arch, mode
        self.csh = ctypes.c_uint64()
        status = _cs.cs_open(arch, mode, ctypes.byref(self.csh))
        if status != CS_ERR_OK:
            raise ValueError("Error: Wrong arch or mode")
            self.csh = None

    def __del__(self):
        if self.csh:
            _cs.cs_close(self.csh)

    def disasm(self, code, offset, count = 0):
        if self.csh is None:
            raise ValueError("Error: Failed to initialize!")
        all_insn = ctypes.POINTER(_cs_insn)()
        res = _cs.cs_disasm_dyn(self.csh, code, len(code), offset, count, ctypes.byref(all_insn))
        if res > 0:
            for i in xrange(res):
                yield cs_insn(self.csh, all_insn[i], self.arch)

            _cs.cs_free(all_insn)
        else:
            yield []

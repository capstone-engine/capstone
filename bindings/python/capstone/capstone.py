# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import arm, arm64, mips, x86

__all__ = [
    'Cs',
    'CsInsn',

    'cs_disasm_quick',
    'cs_version',

    'CS_API_MAJOR',
    'CS_API_MINOR',

    'CS_ARCH_ARM',
    'CS_ARCH_ARM64',
    'CS_ARCH_MIPS',
    'CS_ARCH_X86',

    'CS_MODE_LITTLE_ENDIAN',
    'CS_MODE_BIG_ENDIAN',
    'CS_MODE_16',
    'CS_MODE_32',
    'CS_MODE_64',
    'CS_MODE_ARM',
    'CS_MODE_THUMB',
    'CS_MODE_MICRO',
    'CS_MODE_N64',

    'CS_OPT_SYNTAX',
    'CS_OPT_SYNTAX_INTEL',
    'CS_OPT_SYNTAX_ATT',

    'CS_OPT_DETAIL',
    'CS_OPT_ON',
    'CS_OPT_OFF',

    'CS_ERR_OK',
    'CS_ERR_MEM',
    'CS_ERR_ARCH',
    'CS_ERR_HANDLE',
    'CS_ERR_CSH',
    'CS_ERR_MODE',
    'CS_ERR_OPTION',
]

# Capstone C interface

# API version
CS_API_MAJOR = 1
CS_API_MINOR = 0

# architectures
CS_ARCH_ARM = 0
CS_ARCH_ARM64 = 1
CS_ARCH_MIPS = 2
CS_ARCH_X86 = 3

# disasm mode
CS_MODE_LITTLE_ENDIAN = 0      # little-endian mode (default mode)
CS_MODE_ARM = 0                # ARM mode
CS_MODE_16 = (1 << 1)          # 16-bit mode (for X86, Mips)
CS_MODE_32 = (1 << 2)          # 32-bit mode (for X86, Mips)
CS_MODE_64 = (1 << 3)          # 64-bit mode (for X86, Mips)
CS_MODE_THUMB = (1 << 4)       # ARM's Thumb mode, including Thumb-2
CS_MODE_MICRO = (1 << 4)       # MicroMips mode (MIPS architecture)
CS_MODE_N64 = (1 << 5)         # Nintendo-64 mode (MIPS architecture)
CS_MODE_BIG_ENDIAN = (1 << 31) # big-endian mode

# Capstone option type
CS_OPT_SYNTAX = 1    # Intel X86 asm syntax (CS_ARCH_X86 arch)
CS_OPT_DETAIL = 2   # Break down instruction structure into details

# Capstone option value
CS_OPT_OFF = 0             # Turn OFF an option (CS_OPT_DETAIL)
CS_OPT_SYNTAX_INTEL = 1    # Intel X86 asm syntax - default syntax on X86 (CS_OPT_SYNTAX, CS_ARCH_X86)
CS_OPT_SYNTAX_ATT = 2      # ATT asm syntax (CS_OPT_SYNTAX, CS_ARCH_X86)
CS_OPT_ON = 3              # Turn ON an option - this is default option for CS_OPT_DETAIL

# Capstone error type
CS_ERR_OK = 0      # No error: everything was fine
CS_ERR_MEM = 1     # Out-Of-Memory error: cs_open(), cs_disasm_dyn()
CS_ERR_ARCH = 2    # Unsupported architecture: cs_open()
CS_ERR_HANDLE = 3  # Invalid handle: cs_op_count(), cs_op_index()
CS_ERR_CSH = 4     # Invalid csh argument: cs_close(), cs_errno(), cs_option()
CS_ERR_MODE = 5    # Invalid/unsupported mode: cs_open()
CS_ERR_OPTION = 6  # Invalid/unsupported option: cs_option()


import ctypes, ctypes.util
from os.path import split, join
import distutils.sysconfig


# load all the libs
_lib_path = split(__file__)[0]
_all_libs = ['libcapstone.dll', 'libcapstone.so', 'libcapstone.dylib']
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
        ('arm64', arm64.CsArm64),
        ('arm', arm.CsArm),
        ('mips', mips.CsMips),
        ('x86', x86.CsX86),
    )

# low-level structure for C code
class _cs_insn(ctypes.Structure):
    _fields_ = (
        ('id', ctypes.c_uint),
        ('address', ctypes.c_uint64),
        ('size', ctypes.c_uint16),
        ('bytes', ctypes.c_ubyte * 16),
        ('mnemonic', ctypes.c_char * 32),
        ('op_str', ctypes.c_char * 96),
        ('regs_read', ctypes.c_uint * 32),
        ('regs_read_count', ctypes.c_uint),
        ('regs_write', ctypes.c_uint * 32),
        ('regs_write_count', ctypes.c_uint),
        ('groups', ctypes.c_uint * 8),
        ('groups_count', ctypes.c_uint),
        ('arch', _cs_arch),
    )

# setup all the function prototype
def _setup_prototype(lib, fname, restype, *argtypes):
    getattr(lib, fname).restype = restype
    getattr(lib, fname).argtypes = argtypes

_setup_prototype(_cs, "cs_open", ctypes.c_int, ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(ctypes.c_size_t))
_setup_prototype(_cs, "cs_disasm_dyn", ctypes.c_size_t, ctypes.c_size_t, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t, \
        ctypes.c_uint64, ctypes.c_size_t, ctypes.POINTER(ctypes.POINTER(_cs_insn)))
_setup_prototype(_cs, "cs_free", None, ctypes.c_void_p)
_setup_prototype(_cs, "cs_close", ctypes.c_int, ctypes.c_size_t)
_setup_prototype(_cs, "cs_reg_name", ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint)
_setup_prototype(_cs, "cs_insn_name", ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint)
_setup_prototype(_cs, "cs_op_count", ctypes.c_int, ctypes.c_size_t, ctypes.POINTER(_cs_insn), ctypes.c_uint)
_setup_prototype(_cs, "cs_op_index", ctypes.c_int, ctypes.c_size_t, ctypes.POINTER(_cs_insn), ctypes.c_uint, ctypes.c_uint)
_setup_prototype(_cs, "cs_errno", ctypes.c_int, ctypes.c_size_t)
_setup_prototype(_cs, "cs_option", ctypes.c_int, ctypes.c_size_t, ctypes.c_int, ctypes.c_size_t)
_setup_prototype(_cs, "cs_version", None, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))


# access to error code via @errno of CsError
class CsError(Exception):
    def __init__(self, errno):
        self.errno = errno

    def __str__(self):
        messages = { \
            CS_ERR_MEM: "Out of memory (CsError)",
            CS_ERR_ARCH: "Invalid architecture (CsError)",
            CS_ERR_HANDLE: "Invalid handle (CsError)",
            CS_ERR_CSH: "Invalid csh (CsError)",
            CS_ERR_MODE: "Invalid mode (CsError)",
            CS_ERR_OPTION: "Invalid option (CsError)",
        }
        return messages[self.errno]


def cs_version():
    major = ctypes.c_int()
    minor = ctypes.c_int()
    _cs.cs_version(ctypes.byref(major), ctypes.byref(minor))
    return (major.value, minor.value)


# quick & dirty Python function to disasm raw binary code
def cs_disasm_quick(arch, mode, code, offset, count = 0):
    csh = ctypes.c_size_t()
    status = _cs.cs_open(arch, mode, ctypes.byref(csh))
    if status != CS_ERR_OK:
        raise CsError(status)

    insns = []
    all_insn = ctypes.POINTER(_cs_insn)()
    res = _cs.cs_disasm_dyn(csh, code, len(code), offset, count, ctypes.byref(all_insn))
    if res > 0:
        for i in xrange(res):
            insns.append(CsInsn(csh, all_insn[i], arch))

        _cs.cs_free(all_insn)
    else:
        status = _cs.cs_errno(csh)
        if status != CS_ERR_OK:
            raise CsError(status)

    status = _cs.cs_close(csh)
    if status != CS_ERR_OK:
        raise CsError(status)

    return insns

# Python-style class to disasm code
class CsInsn(object):
    def __init__(self, csh, all_info, arch):
        self.id = all_info.id
        self.address = all_info.address
        self.size = all_info.size
        self.mnemonic = all_info.mnemonic[:]    # copy string
        self.op_str = all_info.op_str[:]    # copy string
        self.regs_read = all_info.regs_read[:all_info.regs_read_count]
        self.regs_write = all_info.regs_write[:all_info.regs_write_count]
        self.groups = all_info.groups[:all_info.groups_count]
        self.bytes = bytearray(all_info.bytes)[:self.size]

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

        self.csh = csh

    # get the last error code
    def errno():
        return _cs.cs_errno(self.csh)

    # get the register name, given the register ID
    def reg_name(self, reg_id):
        return _cs.cs_reg_name(self.csh, reg_id)

    # get the instruction string
    def insn_name(self):
        return _cs.cs_insn_name(self.csh, self.id)

    # verify if this insn belong to group with id as @group_id
    def group(self, group_id):
        return group_id in self.groups

    # verify if this instruction implicitly read register @reg_id
    def reg_read(self, reg_id):
        return reg_id in self.regs_read

    # verify if this instruction implicitly modified register @reg_id
    def reg_write(self, reg_id):
        return reg_id in self.regs_write

    # return number of operands having same operand type @op_type
    def op_count(self, op_type):
        c = 0
        for op in self.operands:
            if op.type == op_type:
                c += 1
        return c

    # get the operand at position @position of all operands having the same type @op_type
    def op_find(self, op_type, position):
        c = 0
        for op in self.operands:
            if op.type == op_type:
                c += 1
            if c == position:
                return op


class Cs(object):
    def __init__(self, arch, mode):
        self.arch, self.mode = arch, mode
        self.csh = ctypes.c_size_t()
        status = _cs.cs_open(arch, mode, ctypes.byref(self.csh))
        if status != CS_ERR_OK:
            self.csh = None
            raise CsError(status)

        if arch == CS_ARCH_X86:
            # Intel syntax is default for X86
            self._syntax = CS_OPT_SYNTAX_INTEL
        else:
            self._syntax = None

        self._detail = True    # by default, get instruction details

    def __del__(self):
        if self.csh:
            status = _cs.cs_close(self.csh)
            if status != CS_ERR_OK:
                raise CsError(status)

    #def option(self, opt_type, opt_value):
    #    return _cs.cs_option(self.csh, opt_type, opt_value)

    @property
    def syntax(self):
        return self._syntax

    @syntax.setter
    def syntax(self, style):
        status = _cs.cs_option(self.csh, CS_OPT_SYNTAX, style)
        if status != CS_ERR_OK:
            raise CsError(status)
        # save syntax
        self._syntax = style

    @property
    def detail(self):
        return self._detail

    @detail.setter
    def detail(self, opt):  # opt is boolean type, so must be either 'True' or 'False'
        if opt == False:
            status = _cs.cs_option(self.csh, CS_OPT_DETAIL, CS_OPT_OFF)
        else:
            status = _cs.cs_option(self.csh, CS_OPT_DETAIL, CS_OPT_ON)
        if status != CS_ERR_OK:
            raise CsError(status)
        # save detail
        self._detail = opt

    def disasm(self, code, offset, count = 0):
        insns = []
        all_insn = ctypes.POINTER(_cs_insn)()
        res = _cs.cs_disasm_dyn(self.csh, code, len(code), offset, count, ctypes.byref(all_insn))
        if res > 0:
            for i in xrange(res):
                insns.append(CsInsn(self.csh, all_insn[i], self.arch))
            _cs.cs_free(all_insn)
        else:
            status = _cs.cs_errno(self.csh)
            if status != CS_ERR_OK:
                raise CsError(status)

        return insns


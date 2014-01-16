# By Dang Hoang Vu <danghvu@gmail.com>, 2014

cimport pyx.ccapstone as cc
import capstone, ctypes
from capstone import arm, x86, mips, ppc, arm64, CsError

class CsDetail:

    def __init__(self, arch, raw_detail = None):
        if not raw_detail:
            return
        detail = ctypes.cast(raw_detail, ctypes.POINTER(capstone._cs_detail)).contents

        self.regs_read = detail.regs_read
        self.regs_write = detail.regs_write
        self.groups = detail.groups

        if arch == capstone.CS_ARCH_ARM:
            (self.cc, self.update_flags, self.writeback, self.operands) = \
                arm.get_arch_info(detail.arch.arm)
        elif arch == capstone.CS_ARCH_ARM64:
            (self.cc, self.update_flags, self.writeback, self.operands) = \
                arm64.get_arch_info(detail.arch.arm64)
        elif arch == capstone.CS_ARCH_X86:
            (self.prefix, self.segment, self.opcode, self.op_size, self.addr_size, \
                self.disp_size, self.imm_size, self.modrm, self.sib, self.disp, \
                self.sib_index, self.sib_scale, self.sib_base, self.operands) = x86.get_arch_info(detail.arch.x86)
        elif arch == capstone.CS_ARCH_MIPS:
                self.operands = mips.get_arch_info(detail.arch.mips)
        elif arch == capstone.CS_ARCH_PPC:
            (self.bc, self.bh, self.update_cr0, self.operands) = \
                ppc.get_arch_info(detail.arch.ppc)


cdef class CsInsn(object):

    cdef cc.cs_insn _raw
    cdef cc.csh _csh
    cdef object _detail

    def __cinit__(self, _detail):
        self._detail = _detail

    def __getattr__(self, name):
        _detail = self._detail
        if not _detail:
            raise CsError(capstone.CS_ERR_DETAIL)
        return getattr(_detail, name)

    @property
    def operands(self):
        return self._detail.operands

    @property
    def id(self):
        return self._raw.id

    @property
    def address(self):
        return self._raw.address

    @property
    def size(self):
        return self._raw.size

    @property
    def bytes(self):
        return bytearray(self._raw.bytes)[:self._raw.size]

    @property
    def mnemonic(self):
        return self._raw.mnemonic

    @property
    def op_str(self):
        return self._raw.op_str

    @property
    def regs_read(self):
        if self._detail:
            detail = self._detail
            return detail.regs_read[:detail.regs_read_count]

        raise CsError(capstone.CS_ERR_DETAIL)

    @property
    def regs_write(self):
        if self._detail:
            detail = self._detail
            return detail.regs_write[:detail.regs_write_count]

        raise CsError(capstone.CS_ERR_DETAIL)

    @property
    def groups(self):
        if self._detail:
            detail = self._detail
            return detail.groups[:detail.groups_count]

        raise CsError(capstone.CS_ERR_DETAIL)

    # get the last error code
    def errno(self):
        return cc.cs_errno(self._csh)

    # get the register name, given the register ID
    def reg_name(self, reg_id):
        return cc.cs_reg_name(self._csh, reg_id)

    # get the instruction string
    def insn_name(self):
        return cc.cs_insn_name(self._csh, self.id)

    # verify if this insn belong to group with id as @group_id
    def group(self, group_id):
        return group_id in self._detail.groups

    # verify if this instruction implicitly read register @reg_id
    def reg_read(self, reg_id):
        return reg_id in self._detail.regs_read

    # verify if this instruction implicitly modified register @reg_id
    def reg_write(self, reg_id):
        return reg_id in self._detail.regs_write

    # return number of operands having same operand type @op_type
    def op_count(self, op_type):
        c = 0
        for op in self._detail.operands:
            if op.type == op_type:
                c += 1
        return c

    # get the operand at position @position of all operands having the same type @op_type
    def op_find(self, op_type, position):
        c = 0
        for op in self._detail.operands:
            if op.type == op_type:
                c += 1
            if c == position:
                return op


cdef class Cs:

    cdef cc.csh csh
    cdef object _cs

    def __cinit__(self, _cs):
        self.csh = <cc.csh> _cs.csh.value
        self._cs = _cs

    def disasm(self, code, addr, count=0):
        cdef cc.cs_insn *allinsn
        cdef res = cc.cs_disasm_ex(self.csh, code, len(code), addr, count, &allinsn)
        detail = self._cs.detail
        arch = self._cs.arch

        for i from 0 <= i < res:
            if detail:
                dummy = CsInsn(CsDetail(arch, <size_t>allinsn[i].detail))
            else:
                dummy = CsInsn(None)

            dummy._raw = allinsn[i]
            dummy._csh = self.csh
            yield dummy

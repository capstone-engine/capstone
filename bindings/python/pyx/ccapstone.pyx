# By Dang Hoang Vu <danghvu@gmail.com>, 2014

cimport pyx.ccapstone as cc
import capstone, ctypes
from . import arm, x86, mips, ppc, arm64, sparc, systemz, xcore, tms320c64x, CsError

_diet = cc.cs_support(capstone.CS_SUPPORT_DIET)


class CsDetail(object):

    def __init__(self, arch, raw_detail = None):
        if not raw_detail:
            return
        detail = ctypes.cast(raw_detail, ctypes.POINTER(capstone._cs_detail)).contents

        self.regs_read = detail.regs_read
        self.regs_read_count = detail.regs_read_count
        self.regs_write = detail.regs_write
        self.regs_write_count = detail.regs_write_count
        self.groups = detail.groups
        self.groups_count = detail.groups_count

        if arch == capstone.CS_ARCH_ARM:
            (self.usermode, self.vector_size, self.vector_data, self.cps_mode, self.cps_flag, \
                self.cc, self.update_flags, self.writeback, self.mem_barrier, self.operands) = \
                arm.get_arch_info(detail.arch.arm)
        elif arch == capstone.CS_ARCH_ARM64:
            (self.cc, self.update_flags, self.writeback, self.operands) = \
                arm64.get_arch_info(detail.arch.arm64)
        elif arch == capstone.CS_ARCH_X86:
            (self.prefix, self.opcode, self.rex, self.addr_size, \
                self.modrm, self.sib, self.disp, \
                self.sib_index, self.sib_scale, self.sib_base, \
                self.xop_cc, self.sse_cc, self.avx_cc, self.avx_sae, self.avx_rm, \
                self.eflags, self.operands) = x86.get_arch_info(detail.arch.x86)
        elif arch == capstone.CS_ARCH_MIPS:
                self.operands = mips.get_arch_info(detail.arch.mips)
        elif arch == capstone.CS_ARCH_PPC:
            (self.bc, self.bh, self.update_cr0, self.operands) = \
                ppc.get_arch_info(detail.arch.ppc)
        elif arch == capstone.CS_ARCH_SPARC:
            (self.cc, self.hint, self.operands) = sparc.get_arch_info(detail.arch.sparc)
        elif arch == capstone.CS_ARCH_SYSZ:
            (self.cc, self.operands) = systemz.get_arch_info(detail.arch.sysz)
        elif arch == capstone.CS_ARCH_XCORE:
                self.operands = xcore.get_arch_info(detail.arch.xcore)
        elif arch == capstone.CS_ARCH_TMS320C64X:
                (self.condition, self.funit, self.parallel, self.operands) = tms320c64x.get_arch_info(self._detail.arch.tms320c64x)


cdef class CsInsn(object):

    cdef cc.cs_insn _raw
    cdef cc.csh _csh
    cdef object _detail

    def __cinit__(self, _detail):
        self._detail = _detail

    # defer to CsDetail structure for everything else.
    def __getattr__(self, name):
        _detail = self._detail
        if not _detail:
            raise CsError(capstone.CS_ERR_DETAIL)
        return getattr(_detail, name)

    # return instruction's operands.
    @property
    def operands(self):
        return self._detail.operands

    # return instruction's ID.
    @property
    def id(self):
        return self._raw.id

    # return instruction's address.
    @property
    def address(self):
        return self._raw.address

    # return instruction's size.
    @property
    def size(self):
        return self._raw.size

    # return instruction's machine bytes (which should have @size bytes).
    @property
    def bytes(self):
        return bytearray(self._raw.bytes[:self._raw.size])

    # return instruction's mnemonic.
    @property
    def mnemonic(self):
        if _diet:
            # Diet engine cannot provide @mnemonic & @op_str
            raise CsError(capstone.CS_ERR_DIET)

        return self._raw.mnemonic

    # return instruction's operands (in string).
    @property
    def op_str(self):
        if _diet:
            # Diet engine cannot provide @mnemonic & @op_str
            raise CsError(capstone.CS_ERR_DIET)

        return self._raw.op_str

    # return list of all implicit registers being read.
    @property
    def regs_read(self):
        if self._raw.id == 0:
            raise CsError(capstone.CS_ERR_SKIPDATA)

        if _diet:
            # Diet engine cannot provide @regs_read
            raise CsError(capstone.CS_ERR_DIET)

        if self._detail:
            detail = self._detail
            return detail.regs_read[:detail.regs_read_count]

        raise CsError(capstone.CS_ERR_DETAIL)

    # return list of all implicit registers being modified
    @property
    def regs_write(self):
        if self._raw.id == 0:
            raise CsError(capstone.CS_ERR_SKIPDATA)

        if _diet:
            # Diet engine cannot provide @regs_write
            raise CsError(capstone.CS_ERR_DIET)

        if self._detail:
            detail = self._detail
            return detail.regs_write[:detail.regs_write_count]

        raise CsError(capstone.CS_ERR_DETAIL)

    # return list of semantic groups this instruction belongs to.
    @property
    def groups(self):
        if self._raw.id == 0:
            raise CsError(capstone.CS_ERR_SKIPDATA)

        if _diet:
            # Diet engine cannot provide @groups
            raise CsError(capstone.CS_ERR_DIET)

        if self._detail:
            detail = self._detail
            return detail.groups[:detail.groups_count]

        raise CsError(capstone.CS_ERR_DETAIL)

    # get the last error code
    def errno(self):
        return cc.cs_errno(self._csh)

    # get the register name, given the register ID
    def reg_name(self, reg_id):
        if self._raw.id == 0:
            raise CsError(capstone.CS_ERR_SKIPDATA)

        if _diet:
            # Diet engine cannot provide register's name
            raise CsError(capstone.CS_ERR_DIET)

        return cc.cs_reg_name(self._csh, reg_id)

    # get the instruction string
    def insn_name(self):
        if _diet:
            # Diet engine cannot provide instruction's name
            raise CsError(capstone.CS_ERR_DIET)

        return cc.cs_insn_name(self._csh, self.id)

    # get the group string
    def group_name(self, group_id):
        if _diet:
            # Diet engine cannot provide group's name
            raise CsError(capstone.CS_ERR_DIET)

        return cc.cs_group_name(self._csh, group_id)

    # verify if this insn belong to group with id as @group_id
    def group(self, group_id):
        if self._raw.id == 0:
            raise CsError(capstone.CS_ERR_SKIPDATA)

        if _diet:
            # Diet engine cannot provide @groups
            raise CsError(capstone.CS_ERR_DIET)

        return group_id in self.groups

    # verify if this instruction implicitly read register @reg_id
    def reg_read(self, reg_id):
        if self._raw.id == 0:
            raise CsError(capstone.CS_ERR_SKIPDATA)

        if _diet:
            # Diet engine cannot provide @regs_read
            raise CsError(capstone.CS_ERR_DIET)

        return reg_id in self.regs_read

    # verify if this instruction implicitly modified register @reg_id
    def reg_write(self, reg_id):
        if self._raw.id == 0:
            raise CsError(capstone.CS_ERR_SKIPDATA)

        if _diet:
            # Diet engine cannot provide @regs_write
            raise CsError(capstone.CS_ERR_DIET)

        return reg_id in self.regs_write

    # return number of operands having same operand type @op_type
    def op_count(self, op_type):
        if self._raw.id == 0:
            raise CsError(capstone.CS_ERR_SKIPDATA)

        c = 0
        for op in self._detail.operands:
            if op.type == op_type:
                c += 1
        return c

    # get the operand at position @position of all operands having the same type @op_type
    def op_find(self, op_type, position):
        if self._raw.id == 0:
            raise CsError(capstone.CS_ERR_SKIPDATA)

        c = 0
        for op in self._detail.operands:
            if op.type == op_type:
                c += 1
            if c == position:
                return op

    # Return (list-of-registers-read, list-of-registers-modified) by this instructions.
    # This includes all the implicit & explicit registers.
    def regs_access(self):
        if self._raw.id == 0:
            raise CsError(capstone.CS_ERR_SKIPDATA)

        cdef cc.uint16_t regs_read[64], regs_write[64]
        cdef cc.uint8_t read_count, write_count

        status = cc.cs_regs_access(self._cs.csh, &self._raw, regs_read, &read_count, regs_write, &write_count)
        if status != capstone.CS_ERR_OK:
            raise CsError(status)

        r1 = []
        for i from 0 <= i < read_count: r1.append(regs_read[i])

        w1 = []
        for i from 0 <= i < write_count: w1.append(regs_write[i])

        return (r1, w1)


cdef class Cs(object):

    cdef cc.csh _csh
    cdef object _cs

    def __cinit__(self, _cs):
        cdef version = cc.cs_version(NULL, NULL)
        if (version != (capstone.CS_API_MAJOR << 8) + capstone.CS_API_MINOR):
            # our binding version is different from the core's API version
            raise CsError(capstone.CS_ERR_VERSION)

        self._csh = <cc.csh> _cs.csh.value
        self._cs = _cs


    # destructor to be called automatically when object is destroyed.
    def __dealloc__(self):
        if self._csh:
            status = cc.cs_close(&self._csh)
            if status != capstone.CS_ERR_OK:
                raise CsError(status)


    # Disassemble binary & return disassembled instructions in CsInsn objects
    def disasm(self, code, addr, count=0):
        cdef cc.cs_insn *allinsn

        cdef res = cc.cs_disasm(self._csh, code, len(code), addr, count, &allinsn)
        detail = self._cs.detail
        arch = self._cs.arch

        try:
            for i from 0 <= i < res:
                if detail:
                    dummy = CsInsn(CsDetail(arch, <size_t>allinsn[i].detail))
                else:
                    dummy = CsInsn(None)

                dummy._raw = allinsn[i]
                dummy._csh = self._csh
                yield dummy
        finally:
            cc.cs_free(allinsn, res)


    # Light function to disassemble binary. This is about 20% faster than disasm() because
    # unlike disasm(), disasm_lite() only return tuples of (address, size, mnemonic, op_str),
    # rather than CsInsn objects.
    def disasm_lite(self, code, addr, count=0):
        # TODO: dont need detail, so we might turn off detail, then turn on again when done
        cdef cc.cs_insn *allinsn

        if _diet:
            # Diet engine cannot provide @mnemonic & @op_str
            raise CsError(capstone.CS_ERR_DIET)

        cdef res = cc.cs_disasm(self._csh, code, len(code), addr, count, &allinsn)

        try:
            for i from 0 <= i < res:
                insn = allinsn[i]
                yield (insn.address, insn.size, insn.mnemonic, insn.op_str)
        finally:
            cc.cs_free(allinsn, res)


# print out debugging info
def debug():
    if cc.cs_support(capstone.CS_SUPPORT_DIET):
        diet = "diet"
    else:
        diet = "standard"

    archs = { "arm": capstone.CS_ARCH_ARM, "arm64": capstone.CS_ARCH_ARM64, \
        "mips": capstone.CS_ARCH_MIPS, "ppc": capstone.CS_ARCH_PPC, \
        "sparc": capstone.CS_ARCH_SPARC, "sysz": capstone.CS_ARCH_SYSZ, \
		"xcore": capstone.CS_ARCH_XCORE, "tms320c64x": capstone.CS_ARCH_TMS320C64X }

    all_archs = ""
    keys = archs.keys()
    keys.sort()
    for k in keys:
        if cc.cs_support(archs[k]):
            all_archs += "-%s" %k

    if cc.cs_support(capstone.CS_ARCH_X86):
        all_archs += "-x86"
        if cc.cs_support(capstone.CS_SUPPORT_X86_REDUCE):
            all_archs += "_reduce"

    (major, minor, _combined) = capstone.cs_version()

    return "Cython-%s%s-c%u.%u-b%u.%u" %(diet, all_archs, major, minor, capstone.CS_API_MAJOR, capstone.CS_API_MINOR)

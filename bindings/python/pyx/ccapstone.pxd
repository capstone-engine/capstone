# By Dang Hoang Vu <danghvu@gmail.com>, 2014

from libcpp cimport bool
from libc.stdint cimport uint8_t, uint64_t, uint16_t

cdef extern from "<capstone/capstone.h>":

    ctypedef size_t csh

    ctypedef enum cs_mode:
        pass

    ctypedef enum cs_arch:
        pass

    ctypedef struct cs_detail:
        pass

    ctypedef struct cs_insn:
        unsigned int id
        uint64_t address
        uint16_t size
        uint8_t bytes[16]
        char mnemonic[32]
        char op_str[160]
        cs_detail *detail

    ctypedef enum cs_err:
        pass

    ctypedef enum cs_opt_type:
        pass

    unsigned int cs_version(int *major, int *minor)

    bool cs_support(int arch)

    cs_err cs_open(cs_arch arch, cs_mode mode, csh *handle)

    cs_err cs_close(csh *handle)

    cs_err cs_errno(csh handle)

    size_t cs_disasm(csh handle,
        const uint8_t *code, size_t code_size,
        uint64_t address,
        size_t count,
        cs_insn **insn)

    cs_err cs_option(csh handle, cs_opt_type type, size_t value)

    void cs_free(cs_insn *insn, size_t count)

    const char *cs_reg_name(csh handle, unsigned int reg_id)

    const char *cs_insn_name(csh handle, unsigned int insn_id)

    const char *cs_group_name(csh handle, unsigned int group_id)

    bool cs_insn_group(csh handle, cs_insn *insn, unsigned int group_id)

    bool cs_reg_read(csh handle, cs_insn *insn, unsigned int reg_id)

    bool cs_reg_write(csh handle, cs_insn *insn, unsigned int reg_id)

    int cs_op_count(csh handle, cs_insn *insn, unsigned int op_type)

    int cs_op_index(csh handle, cs_insn *insn, unsigned int op_type,
        unsigned int position)

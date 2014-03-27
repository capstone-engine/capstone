# This file contains all customized compile options for Capstone.
# Modify it before building step. Consult docs/README for details.

################################################################################
# Specify which archs you want to compile in. By default, we build all archs.
# DO NOT touch the line below.
CAPSTONE_ARCHS =

# Comment out the line below if you don't want to support ARM
CAPSTONE_ARCHS += arm

# Comment out the line below if you don't want to support ARM64
CAPSTONE_ARCHS += aarch64

# Comment out the line below if you don't want to support Mips
CAPSTONE_ARCHS += mips

# Comment out the line below if you don't want to support PowerPC
CAPSTONE_ARCHS += powerpc

# Comment out the line below if you don't want to support Sparc
CAPSTONE_ARCHS += sparc

# Comment out the line below if you don't want to support SystemZ
CAPSTONE_ARCHS += systemz

# Comment out the line below if you don't want to support Intel (16/32/64-bit)
CAPSTONE_ARCHS += x86


################################################################################
# Comment out the line below ('USE_SYS_DYN_MEM = yes'), or change it to
# 'USE_SYS_DYN_MEM = no' if do NOT use malloc/calloc/realloc/free/vsnprintf()
# provided by system for internal dynamic memory management.
#
# NOTE: in that case, specify your own malloc/calloc/realloc/free/vsnprintf()
# functions in your program via API cs_option(), using CS_OPT_MEM option type.

USE_SYS_DYN_MEM = yes


################################################################################
# Change 'CAPSTONE_DIET = no' to 'CAPSTONE_DIET = yes' to make the library
# more compact: use less memory & smaller in binary size.
# This setup will remove the @mnemonic & @op_str data, plus semantic information
# such as @regs_read/write & @group. The amount of binary size reduced is
# up to 50% in some individual archs.
#
# NOTE: we still keep all those related fileds @mnemonic, @op_str, @regs_read,
# @regs_write, @groups, etc in fields in cs_insn structure regardless, but they
# will not be updated (i.e empty), thus become irrelevant.

CAPSTONE_DIET = no


################################################################################
# Change 'CAPSTONE_X86_REDUCE = no' to 'CAPSTONE_X86_REDUCE = yes' to remove
# non-critical instruction sets of X86, making the binary size smaller by ~60%.
# This is desired in special cases, such as OS kernel, where these kind of
# instructions are not used.
#
# The list of instruction sets to be removed includes:
# - Floating Point Unit (FPU)
# - MultiMedia eXtension (MMX)
# - Streaming SIMD Extensions (SSE)
# - 3DNow
# - Advanced Vector Extensions (AVX)
# - Fused Multiply Add Operations (FMA)
# - eXtended Operations (XOP)
# - Transactional Synchronization Extensions (TSX)
#
# Due to this removal, the related instructions are nolonger supported.
#
# By default, Capstone is compiled with 'CAPSTONE_X86_REDUCE = no',
# thus supports complete X86 instructions.

CAPSTONE_X86_REDUCE = no

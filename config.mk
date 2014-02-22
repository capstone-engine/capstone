################################################################################
# Change 'CAPSTONE_DIET = no' to 'CAPSTONE_DIET = yes' to make the library
# more compact.
# This setup will remove all the mnemonic & op_str data, thus reduces the binary
# size by around 200KB.
# NOTE: we still keep @mnemonic & @op_str fields in cs_insn structure regardless,
# but they will not be updated (i.e blank) at the output of disassemble APIs.
CAPSTONE_DIET = no


################################################################################
# Comment out the line below 'USE_SYS_DYN_MEM = yes' if you do not want to use
# system's malloc()/calloc()/realloc()/free() for internal dynamic memory management.
# NOTE: in that case, your program must specify your own malloc/calloc/realloc/free
# functions with cs_option(), using CS_OPT_MEM option type.
USE_SYS_DYN_MEM = yes


################################################################################
# Specify which archs you want to compile in
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

# Comment out the line below if you don't want to support Intel
CAPSTONE_ARCHS += x86

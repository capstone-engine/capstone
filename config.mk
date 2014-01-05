# Comment out the line below 'USE_SYS_DYN_MEM = yes' if you do not want to use
# system's malloc()/calloc()/realloc()/free() for internal dynamic memory management.
# NOTE: in that case, your program must specify your own malloc/calloc/realloc/free
# functions with cs_option(), using CS_OPT_MEM option type.
USE_SYS_DYN_MEM = yes

# Specify which archs you want to compile in
CAPSTONE_ARCHS =

# Comment the line below if you don't want to support ARM
CAPSTONE_ARCHS += arm

# Comment the line below if you don't want to support ARM64
CAPSTONE_ARCHS += aarch64

# Comment the line below if you don't want to support Mips
CAPSTONE_ARCHS += mips

# Comment the line below if you don't want to support X86
CAPSTONE_ARCHS += x86

# Comment the line below if you don't want to support PowerPC
CAPSTONE_ARCHS += powerpc

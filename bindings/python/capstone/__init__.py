# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>
import os
import sys

__all__ = [
    'Cs',
    'CsInsn',

    'cs_disasm_quick',
    'cs_disasm_lite',
    'cs_version',
    'cs_support',
    'version_bind',
    'debug',

    'CS_API_MAJOR',
    'CS_API_MINOR',

    'CS_VERSION_MAJOR',
    'CS_VERSION_MINOR',
    'CS_VERSION_EXTRA',

    'CS_ARCH_ARM',
    'CS_ARCH_AARCH64',
    'CS_ARCH_MIPS',
    'CS_ARCH_X86',
    'CS_ARCH_PPC',
    'CS_ARCH_SPARC',
    'CS_ARCH_SYSTEMZ',
    'CS_ARCH_XCORE',
    'CS_ARCH_M68K',
    'CS_ARCH_TMS320C64X',
    'CS_ARCH_M680X',
    'CS_ARCH_EVM',
    'CS_ARCH_MOS65XX',
    'CS_ARCH_WASM',
    'CS_ARCH_BPF',
    'CS_ARCH_RISCV',
    'CS_ARCH_SH',
    'CS_ARCH_TRICORE',
    'CS_ARCH_ALPHA',
    'CS_ARCH_HPPA',
    'CS_ARCH_LOONGARCH',
    'CS_ARCH_XTENSA',
    'CS_ARCH_ARC',
    'CS_ARCH_ALL',

    'CS_MODE_LITTLE_ENDIAN',
    'CS_MODE_BIG_ENDIAN',
    'CS_MODE_16',
    'CS_MODE_32',
    'CS_MODE_64',
    'CS_MODE_ARM',
    'CS_MODE_THUMB',
    'CS_MODE_MCLASS',
    'CS_MODE_V8',
    'CS_MODE_V9',
    'CS_MODE_QPX',
    'CS_MODE_SPE',
    'CS_MODE_BOOKE',
    'CS_MODE_PS',
    'CS_MODE_MIPS16',
    'CS_MODE_MIPS32',
    'CS_MODE_MIPS64',
    'CS_MODE_MICRO',
    'CS_MODE_MIPS1',
    'CS_MODE_MIPS2',
    'CS_MODE_MIPS32R2',
    'CS_MODE_MIPS32R3',
    'CS_MODE_MIPS32R5',
    'CS_MODE_MIPS32R6',
    'CS_MODE_MIPS3',
    'CS_MODE_MIPS4',
    'CS_MODE_MIPS5',
    'CS_MODE_MIPS64R2',
    'CS_MODE_MIPS64R3',
    'CS_MODE_MIPS64R5',
    'CS_MODE_MIPS64R6',
    'CS_MODE_OCTEON',
    'CS_MODE_OCTEONP',
    'CS_MODE_NANOMIPS',
    'CS_MODE_NMS1',
    'CS_MODE_I7200',
    'CS_MODE_MIPS_NOFLOAT',
    'CS_MODE_MIPS_PTR64',
    'CS_MODE_MICRO32R3',
    'CS_MODE_MICRO32R6',
    'CS_MODE_M68K_000',
    'CS_MODE_M68K_010',
    'CS_MODE_M68K_020',
    'CS_MODE_M68K_030',
    'CS_MODE_M68K_040',
    'CS_MODE_M68K_060',
    'CS_MODE_M680X_6301',
    'CS_MODE_M680X_6309',
    'CS_MODE_M680X_6800',
    'CS_MODE_M680X_6801',
    'CS_MODE_M680X_6805',
    'CS_MODE_M680X_6808',
    'CS_MODE_M680X_6809',
    'CS_MODE_M680X_6811',
    'CS_MODE_M680X_CPU12',
    'CS_MODE_M680X_HCS08',
    'CS_MODE_BPF_CLASSIC',
    'CS_MODE_BPF_EXTENDED',
    'CS_MODE_RISCV32',
    'CS_MODE_RISCV64',
    'CS_MODE_RISCVC',
    'CS_MODE_MOS65XX_6502',
    'CS_MODE_MOS65XX_65C02',
    'CS_MODE_MOS65XX_W65C02',
    'CS_MODE_MOS65XX_65816',
    'CS_MODE_MOS65XX_65816_LONG_M',
    'CS_MODE_MOS65XX_65816_LONG_X',
    'CS_MODE_MOS65XX_65816_LONG_MX',
    'CS_MODE_SH2',
    'CS_MODE_SH2A',
    'CS_MODE_SH3',
    'CS_MODE_SH4',
    'CS_MODE_SH4A',
    'CS_MODE_SHFPU',
    'CS_MODE_SHDSP',
    'CS_MODE_TRICORE_110',
    'CS_MODE_TRICORE_120',
    'CS_MODE_TRICORE_130',
    'CS_MODE_TRICORE_131',
    'CS_MODE_TRICORE_160',
    'CS_MODE_TRICORE_161',
    'CS_MODE_TRICORE_162',
    "CS_MODE_TRICORE_180",
    'CS_MODE_HPPA_11',
    'CS_MODE_HPPA_20',
    'CS_MODE_HPPA_20W',
    'CS_MODE_LOONGARCH32',
    'CS_MODE_LOONGARCH64',
    'CS_MODE_SYSTEMZ_ARCH8',
    'CS_MODE_SYSTEMZ_ARCH9',
    'CS_MODE_SYSTEMZ_ARCH10',
    'CS_MODE_SYSTEMZ_ARCH11',
    'CS_MODE_SYSTEMZ_ARCH12',
    'CS_MODE_SYSTEMZ_ARCH13',
    'CS_MODE_SYSTEMZ_ARCH14',
    'CS_MODE_SYSTEMZ_Z10',
    'CS_MODE_SYSTEMZ_Z196',
    'CS_MODE_SYSTEMZ_ZEC12',
    'CS_MODE_SYSTEMZ_Z13',
    'CS_MODE_SYSTEMZ_Z14',
    'CS_MODE_SYSTEMZ_Z15',
    'CS_MODE_SYSTEMZ_Z16',
    'CS_MODE_SYSTEMZ_GENERIC',

    'CS_OPT_SYNTAX',
    'CS_OPT_SYNTAX_DEFAULT',
    'CS_OPT_SYNTAX_INTEL',
    'CS_OPT_SYNTAX_ATT',
    'CS_OPT_SYNTAX_NOREGNAME',
    'CS_OPT_SYNTAX_MASM',
    'CS_OPT_SYNTAX_MOTOROLA',
    'CS_OPT_SYNTAX_CS_REG_ALIAS',
    'CS_OPT_SYNTAX_NO_DOLLAR',

    'CS_OPT_DETAIL',
    'CS_OPT_DETAIL_REAL',
    'CS_OPT_MODE',
    'CS_OPT_ON',
    'CS_OPT_OFF',

    'CS_OPT_INVALID',
    'CS_OPT_MEM',
    'CS_OPT_SKIPDATA',
    'CS_OPT_SKIPDATA_SETUP',
    'CS_OPT_MNEMONIC',
    'CS_OPT_UNSIGNED',
    'CS_OPT_ONLY_OFFSET_BRANCH',

    'CS_ERR_OK',
    'CS_ERR_MEM',
    'CS_ERR_ARCH',
    'CS_ERR_HANDLE',
    'CS_ERR_CSH',
    'CS_ERR_MODE',
    'CS_ERR_OPTION',
    'CS_ERR_DETAIL',
    'CS_ERR_VERSION',
    'CS_ERR_MEMSETUP',
    'CS_ERR_DIET',
    'CS_ERR_SKIPDATA',
    'CS_ERR_X86_ATT',
    'CS_ERR_X86_INTEL',
    'CS_ERR_X86_MASM',

    'CS_SUPPORT_DIET',
    'CS_SUPPORT_X86_REDUCE',
    'CS_SKIPDATA_CALLBACK',

    'CS_OP_INVALID',
    'CS_OP_REG',
    'CS_OP_IMM',
    'CS_OP_FP',
    'CS_OP_PRED',
    'CS_OP_RESERVED_5',
    'CS_OP_RESERVED_6',
    'CS_OP_RESERVED_7',
    'CS_OP_RESERVED_8',
    'CS_OP_RESERVED_9',
    'CS_OP_RESERVED_10',
    'CS_OP_RESERVED_11',
    'CS_OP_RESERVED_12',
    'CS_OP_RESERVED_13',
    'CS_OP_RESERVED_14',
    'CS_OP_RESERVED_15',
    'CS_OP_SPECIAL',
    'CS_OP_MEM',
    'CS_OP_MEM_REG',
    'CS_OP_MEM_IMM',

    'CS_GRP_INVALID',
    'CS_GRP_JUMP',
    'CS_GRP_CALL',
    'CS_GRP_RET',
    'CS_GRP_INT',
    'CS_GRP_IRET',
    'CS_GRP_PRIVILEGE',
    'CS_GRP_BRANCH_RELATIVE',

    'CS_AC_INVALID',
    'CS_AC_READ',
    'CS_AC_WRITE',

    'CsError',

    '__version__',
]

UINT8_MAX = 0xff
UINT16_MAX = 0xffff

# Capstone C interface

# API version
CS_API_MAJOR = 6
CS_API_MINOR = 0

# Package version
CS_VERSION_MAJOR = CS_API_MAJOR
CS_VERSION_MINOR = CS_API_MINOR
CS_VERSION_EXTRA = 0

__version__ = "%u.%u.%u" % (CS_VERSION_MAJOR, CS_VERSION_MINOR, CS_VERSION_EXTRA)

# architectures
CS_ARCH_ARM = 0
CS_ARCH_AARCH64 = 1
CS_ARCH_SYSTEMZ = 2
CS_ARCH_MIPS = 3
CS_ARCH_X86 = 4
CS_ARCH_PPC = 5
CS_ARCH_SPARC = 6
CS_ARCH_XCORE = 7
CS_ARCH_M68K = 8
CS_ARCH_TMS320C64X = 9
CS_ARCH_M680X = 10
CS_ARCH_EVM = 11
CS_ARCH_MOS65XX = 12
CS_ARCH_WASM = 13
CS_ARCH_BPF = 14
CS_ARCH_RISCV = 15
CS_ARCH_SH = 16
CS_ARCH_TRICORE = 17
CS_ARCH_ALPHA = 18
CS_ARCH_HPPA = 19
CS_ARCH_LOONGARCH = 20
CS_ARCH_XTENSA = 21
CS_ARCH_ARC = 22
CS_ARCH_MAX = 22
CS_ARCH_ALL = 0xFFFF

# disasm mode
CS_MODE_LITTLE_ENDIAN = 0      # little-endian mode (default mode)
CS_MODE_ARM = 0                # ARM mode
CS_MODE_16 = (1 << 1)          # 16-bit mode (for X86)
CS_MODE_32 = (1 << 2)          # 32-bit mode (for X86)
CS_MODE_64 = (1 << 3)          # 64-bit mode (for X86, PPC)
CS_MODE_THUMB = (1 << 4)       # ARM's Thumb mode, including Thumb-2
CS_MODE_MCLASS = (1 << 5)      # ARM's Cortex-M series
CS_MODE_V8 = (1 << 6)          # ARMv8 A32 encodings for ARM
CS_MODE_MICRO = (1 << 4)       # MicroMips mode (MIPS architecture)
CS_MODE_MIPS3 = (1 << 5)       # Mips III ISA
CS_MODE_MIPS32R6 = (1 << 6)    # Mips32r6 ISA
CS_MODE_MIPS2 = (1 << 7)       # Mips II ISA
CS_MODE_V9 = (1 << 4)          # Sparc V9 mode (for Sparc)
CS_MODE_QPX = (1 << 4)         # Quad Processing eXtensions mode (PPC)
CS_MODE_SPE = (1 << 5)         # Signal Processing Engine mode (PPC)
CS_MODE_BOOKE = (1 << 6)       # Book-E mode (PPC)
CS_MODE_PS = (1 << 7)          # Paired-singles mode (PPC)
CS_MODE_AIX_OS = (1 << 8)      # PowerPC AIX-OS
CS_MODE_PWR7 = (1 << 9)        # Power 7
CS_MODE_PWR8 = (1 << 10)       # Power 8
CS_MODE_PWR9 = (1 << 11)       # Power 9
CS_MODE_PWR10 = (1 << 12)      # Power 10
CS_MODE_PPC_ISA_FUTURE = (1 << 13)  # Power ISA Future
CS_MODE_MODERN_AIX_AS = (1 << 14)   # PowerPC AIX-OS with modern assembly
CS_MODE_MSYNC = (1 << 15)      # PowerPC Has only the msync instruction instead of sync. Implies BOOKE
CS_MODE_M68K_000 = (1 << 1)    # M68K 68000 mode
CS_MODE_M68K_010 = (1 << 2)    # M68K 68010 mode
CS_MODE_M68K_020 = (1 << 3)    # M68K 68020 mode
CS_MODE_M68K_030 = (1 << 4)    # M68K 68030 mode
CS_MODE_M68K_040 = (1 << 5)    # M68K 68040 mode
CS_MODE_M68K_060 = (1 << 6)    # M68K 68060 mode
CS_MODE_BIG_ENDIAN = (1 << 31) # big-endian mode
CS_MODE_MIPS16 = CS_MODE_16 # Generic mips16
CS_MODE_MIPS32 = CS_MODE_32 # Generic mips32
CS_MODE_MIPS64 = CS_MODE_64 # Generic mips64
CS_MODE_MICRO = 1 << 4 # microMips
CS_MODE_MIPS1 = 1 << 5 # Mips I ISA Support
CS_MODE_MIPS2 = 1 << 6 # Mips II ISA Support
CS_MODE_MIPS32R2 = 1 << 7 # Mips32r2 ISA Support
CS_MODE_MIPS32R3 = 1 << 8 # Mips32r3 ISA Support
CS_MODE_MIPS32R5 = 1 << 9 # Mips32r5 ISA Support
CS_MODE_MIPS32R6 = 1 << 10 # Mips32r6 ISA Support
CS_MODE_MIPS3 = 1 << 11 # MIPS III ISA Support
CS_MODE_MIPS4 = 1 << 12 # MIPS IV ISA Support
CS_MODE_MIPS5 = 1 << 13 # MIPS V ISA Support
CS_MODE_MIPS64R2 = 1 << 14 # Mips64r2 ISA Support
CS_MODE_MIPS64R3 = 1 << 15 # Mips64r3 ISA Support
CS_MODE_MIPS64R5 = 1 << 16 # Mips64r5 ISA Support
CS_MODE_MIPS64R6 = 1 << 17 # Mips64r6 ISA Support
CS_MODE_OCTEON = 1 << 18 # Octeon cnMIPS Support
CS_MODE_OCTEONP = 1 << 19 # Octeon+ cnMIPS Support
CS_MODE_NANOMIPS = 1 << 20 # Generic nanomips 
CS_MODE_NMS1 = ((1 << 21) | CS_MODE_NANOMIPS) # nanoMips NMS1
CS_MODE_I7200 = ((1 << 22) | CS_MODE_NANOMIPS) # nanoMips I7200
CS_MODE_MIPS_NOFLOAT = 1 << 23 # Disable floating points ops
CS_MODE_MIPS_PTR64 = 1 << 24 # Mips pointers are 64-bit
CS_MODE_MICRO32R3 = (CS_MODE_MICRO | CS_MODE_MIPS32R3) # microMips32r3
CS_MODE_MICRO32R6 = (CS_MODE_MICRO | CS_MODE_MIPS32R6) # microMips32r6
CS_MODE_M680X_6301 = (1 << 1)  # M680X HD6301/3 mode
CS_MODE_M680X_6309 = (1 << 2)  # M680X HD6309 mode
CS_MODE_M680X_6800 = (1 << 3)  # M680X M6800/2 mode
CS_MODE_M680X_6801 = (1 << 4)  # M680X M6801/3 mode
CS_MODE_M680X_6805 = (1 << 5)  # M680X M6805 mode
CS_MODE_M680X_6808 = (1 << 6)  # M680X M68HC08 mode
CS_MODE_M680X_6809 = (1 << 7)  # M680X M6809 mode
CS_MODE_M680X_6811 = (1 << 8)  # M680X M68HC11 mode
CS_MODE_M680X_CPU12 = (1 << 9)  # M680X CPU12 mode
CS_MODE_M680X_HCS08 = (1 << 10)  # M680X HCS08 mode
CS_MODE_BPF_CLASSIC = 0          # Classic BPF mode (default)
CS_MODE_BPF_EXTENDED = (1 << 0)  # Extended BPF mode
CS_MODE_RISCV32 = (1 << 0)       # RISCV32 mode
CS_MODE_RISCV64 = (1 << 1)       # RISCV64 mode
CS_MODE_RISCVC  = (1 << 2)       # RISCV compressed mode
CS_MODE_MOS65XX_6502 = (1 << 1) # MOS65XXX MOS 6502
CS_MODE_MOS65XX_65C02 = (1 << 2) # MOS65XXX WDC 65c02
CS_MODE_MOS65XX_W65C02 = (1 << 3) # MOS65XXX WDC W65c02
CS_MODE_MOS65XX_65816 = (1 << 4) # MOS65XXX WDC 65816, 8-bit m/x
CS_MODE_MOS65XX_65816_LONG_M = (1 << 5) # MOS65XXX WDC 65816, 16-bit m, 8-bit x
CS_MODE_MOS65XX_65816_LONG_X = (1 << 6) # MOS65XXX WDC 65816, 8-bit m, 16-bit x
CS_MODE_MOS65XX_65816_LONG_MX = CS_MODE_MOS65XX_65816_LONG_M | CS_MODE_MOS65XX_65816_LONG_X
CS_MODE_SH2 = 1 << 1   # SH2
CS_MODE_SH2A = 1 << 2  # SH2A
CS_MODE_SH3 = 1 << 3   # SH3
CS_MODE_SH4 = 1 << 4   # SH4
CS_MODE_SH4A = 1 << 5  # SH4A
CS_MODE_SHFPU = 1 << 6 # w/ FPU
CS_MODE_SHDSP = 1 << 7 # w/ DSP
CS_MODE_TRICORE_110 = 1 << 1 # Tricore 1.1
CS_MODE_TRICORE_120 = 1 << 2 # Tricore 1.2
CS_MODE_TRICORE_130 = 1 << 3 # Tricore 1.3
CS_MODE_TRICORE_131 = 1 << 4 # Tricore 1.3.1
CS_MODE_TRICORE_160 = 1 << 5 # Tricore 1.6
CS_MODE_TRICORE_161 = 1 << 6 # Tricore 1.6.1
CS_MODE_TRICORE_162 = 1 << 7 # Tricore 1.6.2
CS_MODE_TRICORE_180 = 1 << 8 # Tricore 1.8.0
CS_MODE_HPPA_11 = 1 << 1 # HPPA 1.1
CS_MODE_HPPA_20 = 1 << 2 # HPPA 2.0
CS_MODE_HPPA_20W = CS_MODE_HPPA_20 | (1 << 3) # HPPA 2.0 wide
CS_MODE_LOONGARCH32 = 1 << 0
CS_MODE_LOONGARCH64 = 1 << 1
CS_MODE_SYSTEMZ_ARCH8 = 1 << 1
CS_MODE_SYSTEMZ_ARCH9 = 1 << 2
CS_MODE_SYSTEMZ_ARCH10 = 1 << 3
CS_MODE_SYSTEMZ_ARCH11 = 1 << 4
CS_MODE_SYSTEMZ_ARCH12 = 1 << 5
CS_MODE_SYSTEMZ_ARCH13 = 1 << 6
CS_MODE_SYSTEMZ_ARCH14 = 1 << 7
CS_MODE_SYSTEMZ_Z10 = 1 << 8
CS_MODE_SYSTEMZ_Z196 = 1 << 9
CS_MODE_SYSTEMZ_ZEC12 = 1 << 10
CS_MODE_SYSTEMZ_Z13 = 1 << 11
CS_MODE_SYSTEMZ_Z14 = 1 << 12
CS_MODE_SYSTEMZ_Z15 = 1 << 13
CS_MODE_SYSTEMZ_Z16 = 1 << 14
CS_MODE_SYSTEMZ_GENERIC = 1 << 15

# Capstone option type
CS_OPT_INVALID = 0   # No option specified
CS_OPT_SYNTAX = 1    # Intel X86 asm syntax (CS_ARCH_X86 arch)
CS_OPT_DETAIL = 2    # Break down instruction structure into details
CS_OPT_MODE = 3      # Change engine's mode at run-time
CS_OPT_MEM = 4       # Change engine's mode at run-time
CS_OPT_SKIPDATA = 5  # Skip data when disassembling
CS_OPT_SKIPDATA_SETUP = 6      # Setup user-defined function for SKIPDATA option
CS_OPT_MNEMONIC = 7  # Customize instruction mnemonic
CS_OPT_UNSIGNED = 8  # Print immediate in unsigned form
CS_OPT_ONLY_OFFSET_BRANCH = 9  # ARM, prints branch immediates without offset.

# Capstone option value
CS_OPT_OFF = 0             # Turn OFF an option - default option of CS_OPT_DETAIL
CS_OPT_ON = 1 << 0              # Turn ON an option (CS_OPT_DETAIL)

# Common instruction operand types - to be consistent across all architectures.
CS_OP_INVALID = 0  # uninitialized/invalid operand.
CS_OP_REG = 1  # Register operand.
CS_OP_IMM = 2  # Immediate operand.
CS_OP_FP  = 3  # Floating-Point operand.
CS_OP_PRED = 4  # Predicate operand.
CS_OP_RESERVED_5 = 5
CS_OP_RESERVED_6 = 6
CS_OP_RESERVED_7 = 7
CS_OP_RESERVED_8 = 8
CS_OP_RESERVED_9 = 9
CS_OP_RESERVED_10 = 10
CS_OP_RESERVED_11 = 11
CS_OP_RESERVED_12 = 12
CS_OP_RESERVED_13 = 13
CS_OP_RESERVED_14 = 14
CS_OP_RESERVED_15 = 15
CS_OP_SPECIAL = 0x10  # Special operands from archs
CS_OP_MEM = 0x80  # Memory operand. Can be ORed with another operand type.
CS_OP_MEM_REG = CS_OP_MEM | CS_OP_REG  # Memory referencing register operand.
CS_OP_MEM_IMM = CS_OP_MEM | CS_OP_IMM  # Memory referencing immediate operand.

# Common instruction groups - to be consistent across all architectures.
CS_GRP_INVALID = 0  # uninitialized/invalid group.
CS_GRP_JUMP    = 1  # all jump instructions (conditional+direct+indirect jumps)
CS_GRP_CALL    = 2  # all call instructions
CS_GRP_RET     = 3  # all return instructions
CS_GRP_INT     = 4  # all interrupt instructions (int+syscall)
CS_GRP_IRET    = 5  # all interrupt return instructions
CS_GRP_PRIVILEGE = 6  # all privileged instructions
CS_GRP_BRANCH_RELATIVE = 7 # all relative branching instructions

# Access types for instruction operands.
CS_AC_INVALID  = 0        # Invalid/uninitialized access type.
CS_AC_READ     = (1 << 0) # Operand that is read from.
CS_AC_WRITE    = (1 << 1) # Operand that is written to.
CS_AC_READ_WRITE = CS_AC_READ | CS_AC_WRITE

# Capstone syntax value
CS_OPT_SYNTAX_DEFAULT = (1 << 1)  # Default assembly syntax of all platforms (CS_OPT_SYNTAX)
CS_OPT_SYNTAX_INTEL = (1 << 2)  # Intel X86 asm syntax - default syntax on X86 (CS_OPT_SYNTAX, CS_ARCH_X86)
CS_OPT_SYNTAX_ATT = (1 << 3)  # ATT asm syntax (CS_OPT_SYNTAX, CS_ARCH_X86)
CS_OPT_SYNTAX_NOREGNAME = (1 << 4)  # Asm syntax prints register name with only number - (CS_OPT_SYNTAX, CS_ARCH_PPC, CS_ARCH_ARM)
CS_OPT_SYNTAX_MASM = (1 << 5)  # MASM syntax (CS_OPT_SYNTAX, CS_ARCH_X86)
CS_OPT_SYNTAX_MOTOROLA = (1 << 6)  # MOS65XX use $ as hex prefix
CS_OPT_SYNTAX_CS_REG_ALIAS = (1 << 7)  # Prints common register alias which are not defined in LLVM (ARM: r9 = sb etc.)
CS_OPT_SYNTAX_PERCENT = (1 << 8)  # Prints the % in front of PPC registers.
CS_OPT_SYNTAX_NO_DOLLAR = (1 << 9) # Does not print the $ in front of Mips, LoongArch registers.
CS_OPT_DETAIL_REAL = (1 << 1)  # If enabled, always sets the real instruction detail.Even if the instruction is an alias.

# Capstone error type
CS_ERR_OK = 0      # No error: everything was fine
CS_ERR_MEM = 1     # Out-Of-Memory error: cs_open(), cs_disasm()
CS_ERR_ARCH = 2    # Unsupported architecture: cs_open()
CS_ERR_HANDLE = 3  # Invalid handle: cs_op_count(), cs_op_index()
CS_ERR_CSH = 4     # Invalid csh argument: cs_close(), cs_errno(), cs_option()
CS_ERR_MODE = 5    # Invalid/unsupported mode: cs_open()
CS_ERR_OPTION = 6  # Invalid/unsupported option: cs_option()
CS_ERR_DETAIL = 7  # Invalid/unsupported option: cs_option()
CS_ERR_MEMSETUP = 8
CS_ERR_VERSION = 9 # Unsupported version (bindings)
CS_ERR_DIET = 10   # Information irrelevant in diet engine
CS_ERR_SKIPDATA = 11 # Access irrelevant data for "data" instruction in SKIPDATA mode
CS_ERR_X86_ATT = 12 # X86 AT&T syntax is unsupported (opt-out at compile time)
CS_ERR_X86_INTEL = 13 # X86 Intel syntax is unsupported (opt-out at compile time)
CS_ERR_X86_MASM = 14 # X86 Intel syntax is unsupported (opt-out at compile time)

# query id for cs_support()
CS_SUPPORT_DIET = CS_ARCH_ALL + 1
CS_SUPPORT_X86_REDUCE = CS_ARCH_ALL+2

# Capstone reverse lookup
CS_AC    = {v:k for k,v in locals().items() if k.startswith('CS_AC_')}
CS_ARCH  = {v:k for k,v in locals().items() if k.startswith('CS_ARCH_')}
CS_ERR   = {v:k for k,v in locals().items() if k.startswith('CS_ERR_')}
CS_GRP   = {v:k for k,v in locals().items() if k.startswith('CS_GRP_')}
CS_MODE  = {v:k for k,v in locals().items() if k.startswith('CS_MODE_')}
CS_OP    = {v:k for k,v in locals().items() if k.startswith('CS_OP_')}
CS_OPT   = {v:k for k,v in locals().items() if k.startswith('CS_OPT_')}

import ctypes, ctypes.util
from os.path import split, join, dirname
import sysconfig
from pathlib import PurePath

import inspect

if sys.version_info >= (3, 9):
    import importlib.resources as resources
else:
    import importlib_resources as resources

if not hasattr(sys.modules[__name__], '__file__'):
    __file__ = inspect.getfile(inspect.currentframe())

if sys.platform == 'darwin':
    _lib = "libcapstone.dylib"
elif sys.platform in ('win32', 'cygwin'):
    _lib = "capstone.dll"
else:
    _lib = "libcapstone.so"

_found = False


def _load_lib(path):
    lib_file = join(path, _lib)
    if os.path.exists(lib_file):
        return ctypes.cdll.LoadLibrary(lib_file)
    else:
        # if we're on linux, try again with .so.5 extension
        if lib_file.endswith('.so'):
            if os.path.exists(lib_file + '.{}'.format(CS_VERSION_MAJOR)):
                return ctypes.cdll.LoadLibrary(lib_file + '.{}'.format(CS_VERSION_MAJOR))
    return None


_cs = None

# Loading attempts, in order
# - user-provided environment variable
# - importlib.resources can get us the path to the local libraries
# - we can get the path to the local libraries by parsing our filename
# - global load
# - python's lib directory
# - last-gasp attempt at some hardcoded paths on darwin and linux

_path_list = [os.getenv('LIBCAPSTONE_PATH', None),
              str(resources.files(__name__) / "lib"),
              join(split(__file__)[0], 'lib'),
              '',
              sysconfig.get_path('platlib'),
              "/usr/local/lib/" if sys.platform == 'darwin' else '/usr/lib64']

for _path in _path_list:
    if _path is None: continue
    _cs = _load_lib(_path)
    if _cs is not None: break
else:
    raise ImportError("ERROR: fail to load the dynamic library.")


# low-level structure for C code

def copy_ctypes(src):
    """Returns a new ctypes object which is a bitwise copy of an existing one"""
    dst = type(src)()
    ctypes.memmove(ctypes.byref(dst), ctypes.byref(src), ctypes.sizeof(type(src)))
    return dst


def copy_ctypes_list(src):
    return [copy_ctypes(n) for n in src]


# Weird import placement because these modules are needed by the below code but need the above functions
from . import arm, aarch64, m68k, mips, ppc, sparc, systemz, x86, xcore, tms320c64x, m680x, evm, mos65xx, wasm, bpf, \
    riscv, sh, tricore, alpha, hppa, loongarch, arc, xtensa


class _cs_arch(ctypes.Union):
    _fields_ = (
        ('aarch64', aarch64.CsAArch64),
        ('arm', arm.CsArm),
        ('m68k', m68k.CsM68K),
        ('mips', mips.CsMips),
        ('x86', x86.CsX86),
        ('ppc', ppc.CsPpc),
        ('sparc', sparc.CsSparc),
        ('systemz', systemz.CsSystemZ),
        ('xcore', xcore.CsXcore),
        ('tms320c64x', tms320c64x.CsTMS320C64x),
        ('m680x', m680x.CsM680x),
        ('evm', evm.CsEvm),
        ('mos65xx', mos65xx.CsMOS65xx),
        ('wasm', wasm.CsWasm),
        ('bpf', bpf.CsBPF),
        ('riscv', riscv.CsRISCV),
        ('sh', sh.CsSH),
        ('tricore', tricore.CsTriCore),
        ('alpha', alpha.CsAlpha),
        ('hppa', hppa.CsHPPA),
        ('loongarch', loongarch.CsLoongArch),
        ('xtensa', xtensa.CsXtensa),
        ('arc', arc.CsARC),
    )


class _cs_detail(ctypes.Structure):
    _fields_ = (
        ('regs_read', ctypes.c_uint16 * 20),
        ('regs_read_count', ctypes.c_ubyte),
        ('regs_write', ctypes.c_uint16 * 47),
        ('regs_write_count', ctypes.c_ubyte),
        ('groups', ctypes.c_ubyte * 16),
        ('groups_count', ctypes.c_ubyte),
        ('writeback', ctypes.c_bool),
        ('arch', _cs_arch),
    )


class _cs_insn(ctypes.Structure):
    _fields_ = (
        ('id', ctypes.c_uint),
        ('alias_id', ctypes.c_uint64),
        ('address', ctypes.c_uint64),
        ('size', ctypes.c_uint16),
        ('bytes', ctypes.c_ubyte * 24),
        ('mnemonic', ctypes.c_char * 32),
        ('op_str', ctypes.c_char * 160),
        ('is_alias', ctypes.c_bool),
        ('usesAliasDetails', ctypes.c_bool),
        ('detail', ctypes.POINTER(_cs_detail)),
    )


# callback for SKIPDATA option
CS_SKIPDATA_CALLBACK = ctypes.CFUNCTYPE(ctypes.c_size_t, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t,
                                        ctypes.c_size_t, ctypes.c_void_p)


class _cs_opt_skipdata(ctypes.Structure):
    _fields_ = (
        ('mnemonic', ctypes.c_char_p),
        ('callback', CS_SKIPDATA_CALLBACK),
        ('user_data', ctypes.c_void_p),
    )


class _cs_opt_mnem(ctypes.Structure):
    _fields_ = (
        ('id', ctypes.c_uint),
        ('mnemonic', ctypes.c_char_p),
    )


# setup all the function prototype
def _setup_prototype(lib, fname, restype, *argtypes):
    getattr(lib, fname).restype = restype
    getattr(lib, fname).argtypes = argtypes


_setup_prototype(_cs, "cs_open", ctypes.c_int, ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(ctypes.c_size_t))
_setup_prototype(_cs, "cs_disasm", ctypes.c_size_t, ctypes.c_size_t, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t, \
        ctypes.c_uint64, ctypes.c_size_t, ctypes.POINTER(ctypes.POINTER(_cs_insn)))
_setup_prototype(_cs, "cs_disasm_iter", ctypes.c_bool, ctypes.c_size_t, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)), ctypes.POINTER(ctypes.c_size_t), \
                 ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(_cs_insn))
_setup_prototype(_cs, "cs_free", None, ctypes.c_void_p, ctypes.c_size_t)
_setup_prototype(_cs, "cs_close", ctypes.c_int, ctypes.POINTER(ctypes.c_size_t))
_setup_prototype(_cs, "cs_reg_name", ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint)
_setup_prototype(_cs, "cs_insn_name", ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint)
_setup_prototype(_cs, "cs_group_name", ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint)
_setup_prototype(_cs, "cs_op_count", ctypes.c_int, ctypes.c_size_t, ctypes.POINTER(_cs_insn), ctypes.c_uint)
_setup_prototype(_cs, "cs_op_index", ctypes.c_int, ctypes.c_size_t, ctypes.POINTER(_cs_insn), ctypes.c_uint, ctypes.c_uint)
_setup_prototype(_cs, "cs_errno", ctypes.c_int, ctypes.c_size_t)
_setup_prototype(_cs, "cs_option", ctypes.c_int, ctypes.c_size_t, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_cs, "cs_version", ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
_setup_prototype(_cs, "cs_support", ctypes.c_bool, ctypes.c_int)
_setup_prototype(_cs, "cs_strerror", ctypes.c_char_p, ctypes.c_int)
_setup_prototype(_cs, "cs_regs_access", ctypes.c_int, ctypes.c_size_t, ctypes.POINTER(_cs_insn), ctypes.POINTER(ctypes.c_uint16*64), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint16*64), ctypes.POINTER(ctypes.c_uint8))


# access to error code via @errno of CsError
class CsError(Exception):
    def __init__(self, errno):
        self.errno = errno

    def __str__(self):
        return _cs.cs_strerror(self.errno).decode()


# return the core's version
def cs_version():
    major = ctypes.c_int()
    minor = ctypes.c_int()
    combined = _cs.cs_version(ctypes.byref(major), ctypes.byref(minor))
    return (major.value, minor.value, combined)


# return the binding's version
def version_bind():
    return (CS_API_MAJOR, CS_API_MINOR, (CS_API_MAJOR << 8) + CS_API_MINOR)


def cs_support(query):
    return _cs.cs_support(query)


# dummy class resembling Cs class, just for cs_disasm_quick()
# this class only need to be referenced to via 2 fields: @csh & @arch
class _dummy_cs(object):
    def __init__(self, csh, arch):
        self.csh = csh
        self.arch = arch
        self._detail = False


# Quick & dirty Python function to disasm raw binary code
# This function return CsInsn objects
# NOTE: you might want to use more efficient Cs class & its methods.
def cs_disasm_quick(arch, mode, code, offset, count=0):
    # verify version compatibility with the core before doing anything
    (major, minor, _combined) = cs_version()
    if major != CS_API_MAJOR or minor != CS_API_MINOR:
        # our binding version is different from the core's API version
        raise CsError(CS_ERR_VERSION)

    csh = ctypes.c_size_t()
    status = _cs.cs_open(arch, mode, ctypes.byref(csh))
    if status != CS_ERR_OK:
        raise CsError(status)

    all_insn = ctypes.POINTER(_cs_insn)()
    res = _cs.cs_disasm(csh, code, len(code), offset, count, ctypes.byref(all_insn))
    if res > 0:
        try:
            for i in range(res):
                yield CsInsn(_dummy_cs(csh, arch), all_insn[i])
        finally:
            _cs.cs_free(all_insn, res)
    else:
        status = _cs.cs_errno(csh)
        if status != CS_ERR_OK:
            raise CsError(status)
        return
        yield

    status = _cs.cs_close(ctypes.byref(csh))
    if status != CS_ERR_OK:
        raise CsError(status)


# Another quick, but lighter function to disasm raw binary code.
# This function is faster than cs_disasm_quick() around 20% because
# cs_disasm_lite() only return tuples of (address, size, mnemonic, op_str),
# rather than CsInsn objects.
# NOTE: you might want to use more efficient Cs class & its methods.
def cs_disasm_lite(arch, mode, code, offset, count=0):
    # verify version compatibility with the core before doing anything
    (major, minor, _combined) = cs_version()
    if major != CS_API_MAJOR or minor != CS_API_MINOR:
        # our binding version is different from the core's API version
        raise CsError(CS_ERR_VERSION)

    if cs_support(CS_SUPPORT_DIET):
        # Diet engine cannot provide @mnemonic & @op_str
        raise CsError(CS_ERR_DIET)

    csh = ctypes.c_size_t()
    status = _cs.cs_open(arch, mode, ctypes.byref(csh))
    if status != CS_ERR_OK:
        raise CsError(status)

    all_insn = ctypes.POINTER(_cs_insn)()
    res = _cs.cs_disasm(csh, code, len(code), offset, count, ctypes.byref(all_insn))
    if res > 0:
        try:
            for i in range(res):
                insn = all_insn[i]
                yield (insn.address, insn.size, insn.mnemonic.decode('ascii'), insn.op_str.decode('ascii'))
        finally:
            _cs.cs_free(all_insn, res)
    else:
        status = _cs.cs_errno(csh)
        if status != CS_ERR_OK:
            raise CsError(status)
        return
        yield

    status = _cs.cs_close(ctypes.byref(csh))
    if status != CS_ERR_OK:
        raise CsError(status)


def _ascii_name_or_default(name, default):
    return default if name is None else name.decode('ascii')


# Python-style class to disasm code
class CsInsn(object):
    def __init__(self, cs, all_info):
        self._raw = copy_ctypes(all_info)
        self._cs = cs
        if self._cs._detail and not self.is_invalid_insn():
            # save detail
            self._raw.detail = ctypes.pointer(all_info.detail._type_())
            ctypes.memmove(ctypes.byref(self._raw.detail[0]), ctypes.byref(all_info.detail[0]),
                           ctypes.sizeof(type(all_info.detail[0])))

    def __repr__(self):
        return '<CsInsn 0x%x [%s]: %s %s>' % (self.address, self.bytes.hex(), self.mnemonic, self.op_str)

    # return if the instruction is invalid
    def is_invalid_insn(self):
        arch = self._cs.arch
        if arch == CS_ARCH_EVM:
            return self.id == evm.EVM_INS_INVALID
        else:
            return self.id == 0

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

    # return instruction's is_alias flag
    @property
    def is_alias(self):
        return self._raw.is_alias

    # return instruction's alias_id
    @property
    def alias_id(self):
        return self._raw.alias_id

    # return instruction's flag if it uses alias details
    @property
    def uses_alias_details(self):
        return self._raw.usesAliasDetails

    # return instruction's machine bytes (which should have @size bytes).
    @property
    def bytes(self):
        return bytearray(self._raw.bytes)[:self._raw.size]

    # return instruction's mnemonic.
    @property
    def mnemonic(self):
        if self._cs._diet:
            # Diet engine cannot provide @mnemonic.
            raise CsError(CS_ERR_DIET)

        return self._raw.mnemonic.decode('ascii')

    # return instruction's operands (in string).
    @property
    def op_str(self):
        if self._cs._diet:
            # Diet engine cannot provide @op_str.
            raise CsError(CS_ERR_DIET)

        return self._raw.op_str.decode('ascii')

    # return list of all implicit registers being read.
    @property
    def regs_read(self):
        if self.is_invalid_insn():
            raise CsError(CS_ERR_SKIPDATA)

        if self._cs._diet:
            # Diet engine cannot provide @regs_read.
            raise CsError(CS_ERR_DIET)

        if self._cs._detail:
            return self._raw.detail.contents.regs_read[:self._raw.detail.contents.regs_read_count]

        raise CsError(CS_ERR_DETAIL)

    # return list of all implicit registers being modified
    @property
    def regs_write(self):
        if self.is_invalid_insn():
            raise CsError(CS_ERR_SKIPDATA)

        if self._cs._diet:
            # Diet engine cannot provide @regs_write
            raise CsError(CS_ERR_DIET)

        if self._cs._detail:
            return self._raw.detail.contents.regs_write[:self._raw.detail.contents.regs_write_count]

        raise CsError(CS_ERR_DETAIL)

    # return list of semantic groups this instruction belongs to.
    @property
    def groups(self):
        if self.is_invalid_insn():
            raise CsError(CS_ERR_SKIPDATA)

        if self._cs._diet:
            # Diet engine cannot provide @groups
            raise CsError(CS_ERR_DIET)

        if self._cs._detail:
            return self._raw.detail.contents.groups[:self._raw.detail.contents.groups_count]

        raise CsError(CS_ERR_DETAIL)

    # return whether instruction has writeback operands.
    @property
    def writeback(self):
        if self.is_invalid_insn():
            raise CsError(CS_ERR_SKIPDATA)

        if self._cs._diet:
            # Diet engine cannot provide @writeback.
            raise CsError(CS_ERR_DIET)

        if self._cs._detail:
            return self._raw.detail.contents.writeback

        raise CsError(CS_ERR_DETAIL)

    def __gen_detail(self):
        if self.is_invalid_insn():
            # do nothing in skipdata mode
            return

        arch = self._cs.arch
        if arch == CS_ARCH_ARM:
            (self.usermode, self.vector_size, self.vector_data, self.cps_mode, self.cps_flag, self.cc, self.vcc, self.update_flags, \
            self.post_index, self.mem_barrier, self.pred_mask, self.operands) = arm.get_arch_info(self._raw.detail.contents.arch.arm)
        elif arch == CS_ARCH_AARCH64:
            (self.cc, self.update_flags, self.post_index, self.operands) = \
                aarch64.get_arch_info(self._raw.detail.contents.arch.aarch64)
        elif arch == CS_ARCH_X86:
            (self.prefix, self.opcode, self.rex, self.addr_size, \
                self.modrm, self.sib, self.disp, \
                self.sib_index, self.sib_scale, self.sib_base, self.xop_cc, self.sse_cc, \
                self.avx_cc, self.avx_sae, self.avx_rm, self.eflags, self.fpu_flags, \
                self.encoding, self.modrm_offset, self.disp_offset, self.disp_size, self.imm_offset, self.imm_size, \
                self.operands) = x86.get_arch_info(self._raw.detail.contents.arch.x86)
        elif arch == CS_ARCH_M68K:
                (self.operands, self.op_size) = m68k.get_arch_info(self._raw.detail.contents.arch.m68k)
        elif arch == CS_ARCH_MIPS:
                self.operands = mips.get_arch_info(self._raw.detail.contents.arch.mips)
        elif arch == CS_ARCH_PPC:
            (self.bc, self.update_cr0, self.format, self.operands) = \
                ppc.get_arch_info(self._raw.detail.contents.arch.ppc)
        elif arch == CS_ARCH_SPARC:
            (self.cc, self.hint, self.operands) = sparc.get_arch_info(self._raw.detail.contents.arch.sparc)
        elif arch == CS_ARCH_SYSTEMZ:
            (self.cc, self.format, self.operands) = systemz.get_arch_info(self._raw.detail.contents.arch.systemz)
        elif arch == CS_ARCH_XCORE:
            (self.operands) = xcore.get_arch_info(self._raw.detail.contents.arch.xcore)
        elif arch == CS_ARCH_TMS320C64X:
            (self.condition, self.funit, self.parallel, self.operands) = tms320c64x.get_arch_info(self._raw.detail.contents.arch.tms320c64x)
        elif arch == CS_ARCH_M680X:
            (self.flags, self.operands) = m680x.get_arch_info(self._raw.detail.contents.arch.m680x)
        elif arch == CS_ARCH_EVM:
            (self.pop, self.push, self.fee) = evm.get_arch_info(self._raw.detail.contents.arch.evm)
        elif arch == CS_ARCH_MOS65XX:
            (self.am, self.modifies_flags, self.operands) = mos65xx.get_arch_info(self._raw.detail.contents.arch.mos65xx)
        elif arch == CS_ARCH_WASM:
            (self.operands) = wasm.get_arch_info(self._raw.detail.contents.arch.wasm)
        elif arch == CS_ARCH_BPF:
            (self.operands) = bpf.get_arch_info(self._raw.detail.contents.arch.bpf)
        elif arch == CS_ARCH_RISCV:
            (self.need_effective_addr, self.operands) = riscv.get_arch_info(self._raw.detail.contents.arch.riscv)
        elif arch == CS_ARCH_SH:
            (self.sh_insn, self.sh_size, self.operands) = sh.get_arch_info(self._raw.detail.contents.arch.sh)
        elif arch == CS_ARCH_TRICORE:
            (self.update_flags, self.operands) = tricore.get_arch_info(self._raw.detail.contents.arch.tricore)
        elif arch == CS_ARCH_ALPHA:
            (self.operands) = alpha.get_arch_info(self._raw.detail.contents.arch.alpha)
        elif arch == CS_ARCH_HPPA:
            (self.operands) = hppa.get_arch_info(self._raw.detail.contents.arch.hppa)
        elif arch == CS_ARCH_LOONGARCH:
            (self.format, self.operands) = loongarch.get_arch_info(self._raw.detail.contents.arch.loongarch)
        elif arch == CS_ARCH_ARC:
            (self.operands) = arc.get_arch_info(self._raw.detail.contents.arch.arc)
        elif arch == CS_ARCH_XTENSA:
            (self.operands) = xtensa.get_arch_info(self._raw.detail.contents.arch.xtensa)

    def __getattr__(self, name):
        if not self._cs._detail:
            raise CsError(CS_ERR_DETAIL)

        attr = object.__getattribute__
        if not attr(self, '_cs')._detail:
            raise AttributeError(f"'CsInsn' has no attribute '{name}'")
        _dict = attr(self, '__dict__')
        if 'operands' not in _dict:
            self.__gen_detail()
        if name not in _dict:
            if self.is_invalid_insn():
                raise CsError(CS_ERR_SKIPDATA)
            raise AttributeError(f"'CsInsn' has no attribute '{name}'")
        return _dict[name]

    # get the last error code
    def errno(self):
        return _cs.cs_errno(self._cs.csh)

    # get the register name, given the register ID
    def reg_name(self, reg_id, default=None):
        if self._cs._diet:
            # Diet engine cannot provide register name
            raise CsError(CS_ERR_DIET)

        return _ascii_name_or_default(_cs.cs_reg_name(self._cs.csh, reg_id), default)

    # get the instruction name
    def insn_name(self, default=None):
        if self._cs._diet:
            # Diet engine cannot provide instruction name
            raise CsError(CS_ERR_DIET)

        if self.is_invalid_insn():
            return default

        return _ascii_name_or_default(_cs.cs_insn_name(self._cs.csh, self.id), default)

    # get the group name
    def group_name(self, group_id, default=None):
        if self._cs._diet:
            # Diet engine cannot provide group name
            raise CsError(CS_ERR_DIET)

        return _ascii_name_or_default(_cs.cs_group_name(self._cs.csh, group_id), default)

    # verify if this insn belong to group with id as @group_id
    def group(self, group_id):
        if self.is_invalid_insn():
            raise CsError(CS_ERR_SKIPDATA)

        if self._cs._diet:
            # Diet engine cannot provide group information
            raise CsError(CS_ERR_DIET)

        return group_id in self.groups

    # verify if this instruction implicitly read register @reg_id
    def reg_read(self, reg_id):
        if self.is_invalid_insn():
            raise CsError(CS_ERR_SKIPDATA)

        if self._cs._diet:
            # Diet engine cannot provide regs_read information
            raise CsError(CS_ERR_DIET)

        return reg_id in self.regs_read

    # verify if this instruction implicitly modified register @reg_id
    def reg_write(self, reg_id):
        if self.is_invalid_insn():
            raise CsError(CS_ERR_SKIPDATA)

        if self._cs._diet:
            # Diet engine cannot provide regs_write information
            raise CsError(CS_ERR_DIET)

        return reg_id in self.regs_write

    # return number of operands having same operand type @op_type
    def op_count(self, op_type):
        if self.is_invalid_insn():
            raise CsError(CS_ERR_SKIPDATA)

        c = 0
        for op in self.operands:
            if op.type == op_type:
                c += 1
        return c

    # get the operand at position @position of all operands having the same type @op_type
    def op_find(self, op_type, position):
        if self.is_invalid_insn():
            raise CsError(CS_ERR_SKIPDATA)

        c = 0
        for op in self.operands:
            if op.type == op_type:
                c += 1
            if c == position:
                return op

    # Return (list-of-registers-read, list-of-registers-modified) by this instructions.
    # This includes all the implicit & explicit registers.
    def regs_access(self):
        if self.is_invalid_insn():
            raise CsError(CS_ERR_SKIPDATA)

        regs_read = (ctypes.c_uint16 * 64)()
        regs_read_count = ctypes.c_uint8()
        regs_write = (ctypes.c_uint16 * 64)()
        regs_write_count = ctypes.c_uint8()

        status = _cs.cs_regs_access(self._cs.csh, self._raw, ctypes.byref(regs_read), ctypes.byref(regs_read_count),
                                    ctypes.byref(regs_write), ctypes.byref(regs_write_count))
        if status != CS_ERR_OK:
            raise CsError(status)

        if regs_read_count.value > 0:
            regs_read = regs_read[:regs_read_count.value]
        else:
            regs_read = []

        if regs_write_count.value > 0:
            regs_write = regs_write[:regs_write_count.value]
        else:
            regs_write = []

        return (regs_read, regs_write)


class Cs(object):
    def __init__(self, arch, mode):
        # verify version compatibility with the core before doing anything
        (major, minor, _combined) = cs_version()
        if major != CS_API_MAJOR or minor != CS_API_MINOR:
            self.csh = None
            # our binding version is different from the core's API version
            raise CsError(CS_ERR_VERSION)

        self.arch, self._mode = arch, mode
        self.csh = ctypes.c_size_t()
        status = _cs.cs_open(arch, mode, ctypes.byref(self.csh))
        if status != CS_ERR_OK:
            self.csh = None
            raise CsError(status)

        try:
            from . import ccapstone
            # rewire disasm to use the faster version
            self.disasm = ccapstone.Cs(self).disasm
        except:
            pass

        if arch == CS_ARCH_X86:
            # Intel syntax is default for X86
            self._syntax = CS_OPT_SYNTAX_INTEL
        else:
            self._syntax = None

        self._detail = False  # by default, do not produce instruction details
        self._imm_unsigned = False  # by default, print immediate operands as signed numbers
        self._diet = cs_support(CS_SUPPORT_DIET)
        self._x86reduce = cs_support(CS_SUPPORT_X86_REDUCE)

        # default mnemonic for SKIPDATA
        self._skipdata_mnem = ".byte"
        self._skipdata_cb = (None, None)
        # store reference to option object to avoid it being freed
        # because C code uses it by reference
        self._skipdata_opt = _cs_opt_skipdata()
        self._skipdata = False

    # destructor to be called automatically when object is destroyed.
    def __del__(self):
        if self.csh:
            try:
                status = _cs.cs_close(ctypes.byref(self.csh))
                if status != CS_ERR_OK:
                    raise CsError(status)
            except: # _cs might be pulled from under our feet
                pass

    def option(self, opt_type, opt_value):
        status = _cs.cs_option(self.csh, opt_type, opt_value)
        if status != CS_ERR_OK:
            raise CsError(status)
        if opt_type == CS_OPT_DETAIL or opt_type == CS_OPT_DETAIL_REAL:
            self._detail = (opt_value & CS_OPT_ON) != 0
        elif opt_type == CS_OPT_SKIPDATA:
            self._skipdata = opt_value == CS_OPT_ON
        elif opt_type == CS_OPT_UNSIGNED:
            self._imm_unsigned = opt_value == CS_OPT_ON

    # is this a diet engine?
    @property
    def diet(self):
        return self._diet

    # is this engine compiled with X86-reduce option?
    @property
    def x86_reduce(self):
        return self._x86reduce

    # return assembly syntax.
    @property
    def syntax(self):
        return self._syntax

    # syntax setter: modify assembly syntax.
    @syntax.setter
    def syntax(self, style):
        status = _cs.cs_option(self.csh, CS_OPT_SYNTAX, style)
        if status != CS_ERR_OK:
            raise CsError(status)
        # save syntax
        self._syntax = style

    # return current skipdata status
    @property
    def skipdata(self):
        return self._skipdata

    # setter: modify skipdata status
    @skipdata.setter
    def skipdata(self, opt):
        if opt == False:
            status = _cs.cs_option(self.csh, CS_OPT_SKIPDATA, CS_OPT_OFF)
        else:
            status = _cs.cs_option(self.csh, CS_OPT_SKIPDATA, CS_OPT_ON)
        if status != CS_ERR_OK:
            raise CsError(status)

        # save this option
        self._skipdata = opt

    @property
    def skipdata_setup(self):
        return (self._skipdata_mnem,) + self._skipdata_cb

    @skipdata_setup.setter
    def skipdata_setup(self, opt):
        _mnem, _cb, _ud = opt
        self._skipdata_opt.mnemonic = _mnem.encode()
        self._skipdata_opt.callback = CS_SKIPDATA_CALLBACK(_cb or 0)
        self._skipdata_opt.user_data = ctypes.cast(_ud, ctypes.c_void_p)
        status = _cs.cs_option(self.csh, CS_OPT_SKIPDATA_SETUP,
                               ctypes.cast(ctypes.byref(self._skipdata_opt), ctypes.c_void_p))
        if status != CS_ERR_OK:
            raise CsError(status)

        self._skipdata_mnem = _mnem
        self._skipdata_cb = (_cb, _ud)

    @property
    def skipdata_mnem(self):
        return self._skipdata_mnem

    @skipdata_mnem.setter
    def skipdata_mnem(self, mnem):
        self.skipdata_setup = (mnem,) + self._skipdata_cb

    @property
    def skipdata_callback(self):
        return self._skipdata_cb

    @skipdata_callback.setter
    def skipdata_callback(self, val):
        if not isinstance(val, tuple):
            val = (val, None)
        func, data = val
        self.skipdata_setup = (self._skipdata_mnem, func, data)

    # customize instruction mnemonic
    def mnemonic_setup(self, id, mnem):
        _mnem_opt = _cs_opt_mnem()
        _mnem_opt.id = id
        if mnem:
            _mnem_opt.mnemonic = mnem.encode()
        else:
            _mnem_opt.mnemonic = mnem
        status = _cs.cs_option(self.csh, CS_OPT_MNEMONIC, ctypes.cast(ctypes.byref(_mnem_opt), ctypes.c_void_p))
        if status != CS_ERR_OK:
            raise CsError(status)

    # check to see if this engine supports a particular arch,
    # or diet mode (depending on @query).
    def support(self, query):
        return cs_support(query)

    # is detail mode enable?
    @property
    def detail(self):
        return self._detail

    # modify detail mode.
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

    # is detail mode enable?
    @property
    def imm_unsigned(self):
        return self._imm_unsigned

    # modify detail mode.
    @imm_unsigned.setter
    def imm_unsigned(self, opt):  # opt is boolean type, so must be either 'True' or 'False'
        if opt == False:
            status = _cs.cs_option(self.csh, CS_OPT_UNSIGNED, CS_OPT_OFF)
        else:
            status = _cs.cs_option(self.csh, CS_OPT_UNSIGNED, CS_OPT_ON)
        if status != CS_ERR_OK:
            raise CsError(status)
        # save detail
        self._imm_unsigned = opt

    # return disassembly mode of this engine.
    @property
    def mode(self):
        return self._mode

    # modify engine's mode at run-time.
    @mode.setter
    def mode(self, opt):  # opt is new disasm mode, of int type
        status = _cs.cs_option(self.csh, CS_OPT_MODE, opt)
        if status != CS_ERR_OK:
            raise CsError(status)
        # save mode
        self._mode = opt

    # get the last error code
    def errno(self):
        return _cs.cs_errno(self.csh)

    # get the register name, given the register ID
    def reg_name(self, reg_id, default=None):
        if self._diet:
            # Diet engine cannot provide register name
            raise CsError(CS_ERR_DIET)

        return _ascii_name_or_default(_cs.cs_reg_name(self.csh, reg_id), default)

    # get the instruction name, given the instruction ID
    def insn_name(self, insn_id, default=None):
        if self._diet:
            # Diet engine cannot provide instruction name
            raise CsError(CS_ERR_DIET)

        return _ascii_name_or_default(_cs.cs_insn_name(self.csh, insn_id), default)

    # get the group name
    def group_name(self, group_id, default=None):
        if self._diet:
            # Diet engine cannot provide group name
            raise CsError(CS_ERR_DIET)

        return _ascii_name_or_default(_cs.cs_group_name(self.csh, group_id), default)

    # Disassemble binary & return disassembled instructions in CsInsn objects
    def disasm(self, code, offset, count=0):
        all_insn = ctypes.POINTER(_cs_insn)()
        # Pass a bytearray by reference
        size = len(code)
        view = memoryview(code)
        if not view.readonly:
            code = ctypes.byref(ctypes.c_char.from_buffer(view))
        elif not isinstance(code, bytes):
            code = view.tobytes()
        res = _cs.cs_disasm(self.csh, code, size, offset, count, ctypes.byref(all_insn))
        if res > 0:
            try:
                for i in range(res):
                    yield CsInsn(self, all_insn[i])
            finally:
                _cs.cs_free(all_insn, res)
        else:
            status = _cs.cs_errno(self.csh)
            if status != CS_ERR_OK:
                raise CsError(status)
            return
            yield

    # This function matches the cs_disasm_iter implementation which
    # *should* be much faster via the C API due to pre-allocating
    # memory (https://www.capstone-engine.org/iteration.html).
    # Note: It is unclear whether this function via the Python
    # binding provides the same speedup like cs_disasm_lite.
    def disasm_iter(self, code, offset):
        if self._diet:
            # Diet engine cannot provide @mnemonic & @op_str
            raise CsError(CS_ERR_DIET)
        insn = _cs_insn()
        size = ctypes.c_size_t(len(code))

        # Pass a bytearray by reference
        view = memoryview(code)
        code = ctypes.pointer(ctypes.c_char.from_buffer_copy(view))
        if view.readonly:
            code = (ctypes.c_char * len(view)).from_buffer_copy(view)
        else:
            code = ctypes.pointer(ctypes.c_char.from_buffer(view))

        # since we are taking a pointer to a pointer, ctypes does not do
        # the typical auto conversion, so we have to cast it here.
        code = ctypes.cast(code, ctypes.POINTER(ctypes.c_char))
        address = ctypes.c_uint64(offset)
        while _cs.cs_disasm_iter(self.csh, ctypes.byref(code), ctypes.byref(size), ctypes.byref(address),
                                 ctypes.byref(insn)):
            yield (insn.address, insn.size, insn.mnemonic.decode('ascii'), insn.op_str.decode('ascii'))

    # Light function to disassemble binary. This is about 20% faster than disasm() because
    # unlike disasm(), disasm_lite() only return tuples of (address, size, mnemonic, op_str),
    # rather than CsInsn objects.
    def disasm_lite(self, code, offset, count=0):
        if self._diet:
            # Diet engine cannot provide @mnemonic & @op_str
            raise CsError(CS_ERR_DIET)

        all_insn = ctypes.POINTER(_cs_insn)()
        size = len(code)
        # Pass a bytearray by reference
        view = memoryview(code)
        if not view.readonly:
            code = ctypes.byref(ctypes.c_char.from_buffer(view))
        elif not isinstance(code, bytes):
            code = view.tobytes()
        res = _cs.cs_disasm(self.csh, code, size, offset, count, ctypes.byref(all_insn))
        if res > 0:
            try:
                for i in range(res):
                    insn = all_insn[i]
                    yield (insn.address, insn.size, insn.mnemonic.decode('ascii'), insn.op_str.decode('ascii'))
            finally:
                _cs.cs_free(all_insn, res)
        else:
            status = _cs.cs_errno(self.csh)
            if status != CS_ERR_OK:
                raise CsError(status)
            return
            yield


# print out debugging info
def debug():
    # is Cython there?
    try:
        from . import ccapstone
        return ccapstone.debug()
    except:
        # no Cython, fallback to Python code below
        pass

    if cs_support(CS_SUPPORT_DIET):
        diet = "diet"
    else:
        diet = "standard"

    archs = {
        "arm": CS_ARCH_ARM, "aarch64": CS_ARCH_AARCH64, "m68k": CS_ARCH_M68K,
        "mips": CS_ARCH_MIPS, "ppc": CS_ARCH_PPC, "sparc": CS_ARCH_SPARC,
        "systemz": CS_ARCH_SYSTEMZ, 'xcore': CS_ARCH_XCORE, "tms320c64x": CS_ARCH_TMS320C64X,
        "m680x": CS_ARCH_M680X, 'evm': CS_ARCH_EVM, 'mos65xx': CS_ARCH_MOS65XX,
        'bpf': CS_ARCH_BPF, 'riscv': CS_ARCH_RISCV, 'tricore': CS_ARCH_TRICORE,
        'wasm': CS_ARCH_WASM, 'sh': CS_ARCH_SH, 'alpha': CS_ARCH_ALPHA,
        'hppa': CS_ARCH_HPPA, 'loongarch': CS_ARCH_LOONGARCH, 'xtensa': CS_ARCH_XTENSA, 
        'arc': CS_ARCH_ARC
    }

    all_archs = ""
    keys = archs.keys()
    for k in sorted(keys):
        if cs_support(archs[k]):
            all_archs += "-%s" % k

    if cs_support(CS_ARCH_X86):
        all_archs += "-x86"
        if cs_support(CS_SUPPORT_X86_REDUCE):
            all_archs += "_reduce"

    (major, minor, _combined) = cs_version()

    return "python-%s%s-c%u.%u-b%u.%u" % (diet, all_archs, major, minor, CS_API_MAJOR, CS_API_MINOR)

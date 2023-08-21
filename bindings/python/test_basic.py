#!/usr/bin/env python
# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

from __future__ import print_function
from capstone import *
import binascii
import sys

from xprint import to_hex

_python3 = sys.version_info.major == 3


X86_CODE16 = b"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00"
X86_CODE32 = b"\xba\xcd\xab\x00\x00\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00"
X86_CODE64 = b"\x55\x48\x8b\x05\xb8\x13\x00\x00"
ARM_CODE = b"\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"
ARM_CODE2 = b"\x10\xf1\x10\xe7\x11\xf2\x31\xe7\xdc\xa1\x2e\xf3\xe8\x4e\x62\xf3"
THUMB_CODE = b"\x70\x47\xeb\x46\x83\xb0\xc9\x68"
THUMB_CODE2 = b"\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0"
THUMB_MCLASS = b"\xef\xf3\x02\x80"
ARMV8 = b"\xe0\x3b\xb2\xee\x42\x00\x01\xe1\x51\xf0\x7f\xf5"
MIPS_CODE = b"\x0C\x10\x00\x97\x00\x00\x00\x00\x24\x02\x00\x0c\x8f\xa2\x00\x00\x34\x21\x34\x56"
MIPS_CODE2 = b"\x56\x34\x21\x34\xc2\x17\x01\x00"
MIPS_32R6M = b"\x00\x07\x00\x07\x00\x11\x93\x7c\x01\x8c\x8b\x7c\x00\xc7\x48\xd0"
MIPS_32R6 = b"\xec\x80\x00\x19\x7c\x43\x22\xa0"
ARM64_CODE = b"\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9"
PPC_CODE = b"\x80\x20\x00\x00\x80\x3f\x00\x00\x10\x43\x23\x0e\xd0\x44\x00\x80\x4c\x43\x22\x02\x2d\x03\x00\x80\x7c\x43\x20\x14\x7c\x43\x20\x93\x4f\x20\x00\x21\x4c\xc8\x00\x21"
PPC_CODE2 = b"\x10\x60\x2a\x10\x10\x64\x28\x88\x7c\x4a\x5d\x0f"
SPARC_CODE = b"\x80\xa0\x40\x02\x85\xc2\x60\x08\x85\xe8\x20\x01\x81\xe8\x00\x00\x90\x10\x20\x01\xd5\xf6\x10\x16\x21\x00\x00\x0a\x86\x00\x40\x02\x01\x00\x00\x00\x12\xbf\xff\xff\x10\xbf\xff\xff\xa0\x02\x00\x09\x0d\xbf\xff\xff\xd4\x20\x60\x00\xd4\x4e\x00\x16\x2a\xc2\x80\x03"
SPARCV9_CODE = b"\x81\xa8\x0a\x24\x89\xa0\x10\x20\x89\xa0\x1a\x60\x89\xa0\x00\xe0"
SYSZ_CODE = b"\xed\x00\x00\x00\x00\x1a\x5a\x0f\x1f\xff\xc2\x09\x80\x00\x00\x00\x07\xf7\xeb\x2a\xff\xff\x7f\x57\xe3\x01\xff\xff\x7f\x57\xeb\x00\xf0\x00\x00\x24\xb2\x4f\x00\x78"
XCORE_CODE = b"\xfe\x0f\xfe\x17\x13\x17\xc6\xfe\xec\x17\x97\xf8\xec\x4f\x1f\xfd\xec\x37\x07\xf2\x45\x5b\xf9\xfa\x02\x06\x1b\x10"
M68K_CODE = b"\xd4\x40\x87\x5a\x4e\x71\x02\xb4\xc0\xde\xc0\xde\x5c\x00\x1d\x80\x71\x12\x01\x23\xf2\x3c\x44\x22\x40\x49\x0e\x56\x54\xc5\xf2\x3c\x44\x00\x44\x7a\x00\x00\xf2\x00\x0a\x28\x4E\xB9\x00\x00\x00\x12\x4E\x75"
TMS320C64X_CODE = b"\x01\xac\x88\x40\x81\xac\x88\x43\x00\x00\x00\x00\x02\x90\x32\x96\x02\x80\x46\x9e\x05\x3c\x83\xe6\x0b\x0c\x8b\x24"
M680X_CODE = b"\x06\x10\x19\x1a\x55\x1e\x01\x23\xe9\x31\x06\x34\x55\xa6\x81\xa7\x89\x7f\xff\xa6\x9d\x10\x00\xa7\x91\xa6\x9f\x10\x00\x11\xac\x99\x10\x00\x39"
WASM_CODE = b"\x20\x00\x20\x01\x41\x20\x10\xc9\x01\x45\x0b"
RISCV_CODE32 = b"\x37\x34\x00\x00\x97\x82\x00\x00\xef\x00\x80\x00\xef\xf0\x1f\xff\xe7\x00\x45\x00\xe7\x00\xc0\xff\x63\x05\x41\x00\xe3\x9d\x61\xfe\x63\xca\x93\x00\x63\x53\xb5\x00\x63\x65\xd6\x00\x63\x76\xf7\x00\x03\x88\x18\x00\x03\x99\x49\x00\x03\xaa\x6a\x00\x03\xcb\x2b\x01\x03\xdc\x8c\x01\x23\x86\xad\x03\x23\x9a\xce\x03\x23\x8f\xef\x01\x93\x00\xe0\x00\x13\xa1\x01\x01\x13\xb2\x02\x7d\x13\xc3\x03\xdd\x13\xe4\xc4\x12\x13\xf5\x85\x0c\x13\x96\xe6\x01\x13\xd7\x97\x01\x13\xd8\xf8\x40\x33\x89\x49\x01\xb3\x0a\x7b\x41\x33\xac\xac\x01\xb3\x3d\xde\x01\x33\xd2\x62\x40\xb3\x43\x94\x00\x33\xe5\xc5\x00\xb3\x76\xf7\x00\xb3\x54\x39\x01\xb3\x50\x31\x00\x33\x9f\x0f\x00"
RISCV_CODE64 = b"\x13\x04\xa8\x7a"


all_tests = (
        (CS_ARCH_X86, CS_MODE_16, X86_CODE16, "X86 16bit (Intel syntax)", None),
        (CS_ARCH_X86, CS_MODE_32, X86_CODE32, "X86 32bit (ATT syntax)", CS_OPT_SYNTAX_ATT),
        (CS_ARCH_X86, CS_MODE_32, X86_CODE32, "X86 32 (Intel syntax)", None),
        (CS_ARCH_X86, CS_MODE_32, X86_CODE32, "X86 32 (MASM syntax)", CS_OPT_SYNTAX_MASM),
        (CS_ARCH_X86, CS_MODE_64, X86_CODE64, "X86 64 (Intel syntax)", None),
        (CS_ARCH_ARM, CS_MODE_ARM, ARM_CODE, "ARM", None),
        (CS_ARCH_ARM, CS_MODE_THUMB, THUMB_CODE2, "THUMB-2", None),
        (CS_ARCH_ARM, CS_MODE_ARM, ARM_CODE2, "ARM: Cortex-A15 + NEON", None),
        (CS_ARCH_ARM, CS_MODE_THUMB, THUMB_CODE, "THUMB", None),
        (CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS, THUMB_MCLASS, "Thumb-MClass", None),
        (CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_V8, ARMV8, "Arm-V8", None),
        (CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN, MIPS_CODE, "MIPS-32 (Big-endian)", None),
        (CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN, MIPS_CODE2, "MIPS-64-EL (Little-endian)", None),
        (CS_ARCH_MIPS, CS_MODE_MIPS32R6 + CS_MODE_MICRO + CS_MODE_BIG_ENDIAN, MIPS_32R6M, "MIPS-32R6 | Micro (Big-endian)", None),
        (CS_ARCH_MIPS, CS_MODE_MIPS32R6 + CS_MODE_BIG_ENDIAN, MIPS_32R6, "MIPS-32R6 (Big-endian)", None),
        (CS_ARCH_ARM64, CS_MODE_ARM, ARM64_CODE, "ARM-64", None),
        (CS_ARCH_PPC, CS_MODE_BIG_ENDIAN, PPC_CODE, "PPC-64", None),
        (CS_ARCH_PPC, CS_MODE_BIG_ENDIAN, PPC_CODE, "PPC-64, print register with number only", CS_OPT_SYNTAX_NOREGNAME),
        (CS_ARCH_PPC, CS_MODE_BIG_ENDIAN + CS_MODE_QPX, PPC_CODE2, "PPC-64 + QPX", CS_OPT_SYNTAX_NOREGNAME),
        (CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN, SPARC_CODE, "Sparc", None),
        (CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN + CS_MODE_V9, SPARCV9_CODE, "SparcV9", None),
        (CS_ARCH_SYSZ, 0, SYSZ_CODE, "SystemZ", None),
        (CS_ARCH_XCORE, 0, XCORE_CODE, "XCore", None),
        (CS_ARCH_M68K, CS_MODE_BIG_ENDIAN | CS_MODE_M68K_040, M68K_CODE, "M68K (68040)", None),
        (CS_ARCH_TMS320C64X, 0, TMS320C64X_CODE, "TMS320C64x", None),
        (CS_ARCH_M680X, CS_MODE_M680X_6809, M680X_CODE, "M680X_M6809", None),
        (CS_ARCH_WASM, 0, WASM_CODE, "WASM", None),
        (CS_ARCH_RISCV, CS_MODE_RISCV32, RISCV_CODE32, "RISCV32", None),
        (CS_ARCH_RISCV, CS_MODE_RISCV64, RISCV_CODE64, "RISCV64", None),
)

# ## Test cs_disasm_quick()
def test_cs_disasm_quick():
    for arch, mode, code, comment, syntax in all_tests:
        print('*' * 40)
        print("Platform: %s" % comment)
        print("Disasm:"),
        print(to_hex(code))
        for insn in cs_disasm_quick(arch, mode, code, 0x1000):
            print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
        print()


def test_different_data_formats():
    if _python3:
        data = bytes.fromhex('4831C948F7E1043B48BB0A2F62696E2F2F736852530A545F5257545E0F05')
    else:
        data = bytes(bytearray.fromhex('4831C948F7E1043B48BB0A2F62696E2F2F736852530A545F5257545E0F05'))
    mnemonics = ['xor', 'mul', 'add', 'movabs', 'push', 'pop', 'push', 'push', 'push', 'pop', 'syscall']
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    for name, code in (
        ('bytearray', bytearray(data)),
        ('memoryview of bytearray', memoryview(bytearray(data))),
        ('memoryview of data', memoryview(data)),
        ('raw data', data)
    ):
        if mnemonics != [op for  _, _, op, _ in disassembler.disasm_lite(code, 0)]:
            print('failure in disassemble-lite for %s.' % name)
        if mnemonics != [instruction.mnemonic for instruction in disassembler.disasm(code, 0)]:
            print('failure in disassemble-full for %s.' % name)


# ## Test class Cs
def test_class():
    for arch, mode, code, comment, syntax in all_tests:
        print('*' * 16)
        print("Platform: %s" % comment)
        print("Code: %s" % to_hex(code))
        print("Disasm:")

        try:
            md = Cs(arch, mode)

            if syntax is not None:
                md.syntax = syntax

            for insn in md.disasm(code, 0x1000):
                # bytes = binascii.hexlify(insn.bytes)
                # print("0x%x:\t%s\t%s\t// hex-code: %s" %(insn.address, insn.mnemonic, insn.op_str, bytes))
                print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

            print("0x%x:" % (insn.address + insn.size))
            print()
        except CsError as e:
            print("ERROR: %s" % e)


# test_cs_disasm_quick()
# print ("*" * 40)
if __name__ == '__main__':
    test_class()
    test_different_data_formats()

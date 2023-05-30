#!/usr/bin/python
# Test tool to compare Capstone output with llvm-mc. By Nguyen Anh Quynh, 2014
import sys
import os
from capstone import *

def test_file(fname):
    print("Test %s" %fname);
    f = open(fname)
    lines = f.readlines()
    f.close()

    if not lines[0].startswith('# '):
        print("ERROR: decoding information is missing")
        return

    # skip '# ' at the front, then split line to get out hexcode
    # Note: option can be '', or 'None'
    #print lines[0]
    #print lines[0][2:].split(', ')
    (arch, mode, option) = lines[0][2:].split(', ')
    mode = mode.replace(' ', '')
    option = option.strip()

    archs = {
        "CS_ARCH_ARM": CS_ARCH_ARM,
        "CS_ARCH_ARM64": CS_ARCH_ARM64,
        "CS_ARCH_MIPS": CS_ARCH_MIPS,
        "CS_ARCH_PPC": CS_ARCH_PPC,
        "CS_ARCH_SPARC": CS_ARCH_SPARC,
        "CS_ARCH_SYSZ": CS_ARCH_SYSZ,
        "CS_ARCH_X86": CS_ARCH_X86,
        "CS_ARCH_XCORE": CS_ARCH_XCORE,
        "CS_ARCH_RISCV": CS_ARCH_RISCV,
        "CS_ARCH_TRICORE": CS_ARCH_TRICORE,
    }
    
    modes = {
        "CS_MODE_16": CS_MODE_16,
        "CS_MODE_32": CS_MODE_32,
        "CS_MODE_64": CS_MODE_64,
        "CS_MODE_MIPS32": CS_MODE_MIPS32,
        "CS_MODE_MIPS64": CS_MODE_MIPS64,
        "0": CS_MODE_ARM,
        "CS_MODE_ARM": CS_MODE_ARM,
        "CS_MODE_THUMB": CS_MODE_THUMB,
        "CS_MODE_ARM+CS_MODE_V8": CS_MODE_ARM+CS_MODE_V8,
        "CS_MODE_THUMB+CS_MODE_V8": CS_MODE_THUMB+CS_MODE_V8,
        "CS_MODE_THUMB+CS_MODE_MCLASS": CS_MODE_THUMB+CS_MODE_MCLASS,
        "CS_MODE_LITTLE_ENDIAN": CS_MODE_LITTLE_ENDIAN,
        "CS_MODE_BIG_ENDIAN": CS_MODE_BIG_ENDIAN,
        "CS_MODE_64+CS_MODE_LITTLE_ENDIAN": CS_MODE_64+CS_MODE_LITTLE_ENDIAN,
        "CS_MODE_64+CS_MODE_BIG_ENDIAN": CS_MODE_64+CS_MODE_BIG_ENDIAN,
        "CS_MODE_MIPS32+CS_MODE_MICRO": CS_MODE_MIPS32+CS_MODE_MICRO,
        "CS_MODE_MIPS32+CS_MODE_MICRO+CS_MODE_BIG_ENDIAN": CS_MODE_MIPS32+CS_MODE_MICRO+CS_MODE_BIG_ENDIAN,
        "CS_MODE_MIPS32+CS_MODE_BIG_ENDIAN+CS_MODE_MICRO": CS_MODE_MIPS32+CS_MODE_MICRO+CS_MODE_BIG_ENDIAN,
        "CS_MODE_BIG_ENDIAN+CS_MODE_V9": CS_MODE_BIG_ENDIAN + CS_MODE_V9,
        "CS_MODE_MIPS32+CS_MODE_BIG_ENDIAN": CS_MODE_MIPS32+CS_MODE_BIG_ENDIAN,
        "CS_MODE_MIPS32+CS_MODE_LITTLE_ENDIAN": CS_MODE_MIPS32+CS_MODE_LITTLE_ENDIAN,
        "CS_MODE_MIPS64+CS_MODE_LITTLE_ENDIAN": CS_MODE_MIPS64+CS_MODE_LITTLE_ENDIAN,
        "CS_MODE_MIPS64+CS_MODE_BIG_ENDIAN": CS_MODE_MIPS64+CS_MODE_BIG_ENDIAN,
        "CS_MODE_RISCV32": CS_MODE_RISCV32,
        "CS_MODE_RISCV64": CS_MODE_RISCV64,
        "CS_MODE_TRICORE_110": CS_MODE_TRICORE_110,
        "CS_MODE_TRICORE_120": CS_MODE_TRICORE_120,
        "CS_MODE_TRICORE_130": CS_MODE_TRICORE_130,
        "CS_MODE_TRICORE_131": CS_MODE_TRICORE_131,
        "CS_MODE_TRICORE_160": CS_MODE_TRICORE_160,
        "CS_MODE_TRICORE_161": CS_MODE_TRICORE_161,
        "CS_MODE_TRICORE_162": CS_MODE_TRICORE_162,
    }

    mc_modes = {
        ("CS_ARCH_X86", "CS_MODE_32"): 0,
        ("CS_ARCH_X86", "CS_MODE_64"): 1,
        ("CS_ARCH_ARM", "CS_MODE_ARM"): 2,
        ("CS_ARCH_ARM", "CS_MODE_THUMB"): 3,
        ("CS_ARCH_ARM", "CS_MODE_ARM+CS_MODE_V8"): 4,
        ("CS_ARCH_ARM", "CS_MODE_THUMB+CS_MODE_V8"): 5,
        ("CS_ARCH_ARM", "CS_MODE_THUMB+CS_MODE_MCLASS"): 6,
        ("CS_ARCH_ARM64", "0"): 7,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32+CS_MODE_BIG_ENDIAN"): 8,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32+CS_MODE_MICRO"): 9,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS64"): 10,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32"): 11,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS64+CS_MODE_BIG_ENDIAN"): 12,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32+CS_MODE_MICRO+CS_MODE_BIG_ENDIAN"): 13,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32+CS_MODE_BIG_ENDIAN+CS_MODE_MICRO"): 13,
        ("CS_ARCH_PPC", "CS_MODE_BIG_ENDIAN"): 14,
        ("CS_ARCH_SPARC", "CS_MODE_BIG_ENDIAN"): 15,
        ("CS_ARCH_SPARC", "CS_MODE_BIG_ENDIAN+CS_MODE_V9"): 16,
        ("CS_ARCH_SYSZ", "0"): 17,
        ("CS_ARCH_XCORE", "0"): 18,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32R6+CS_MODE_BIG_ENDIAN"): 19,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32R6+CS_MODE_MICRO+CS_MODE_BIG_ENDIAN"): 20,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32R6"): 21,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32R6+CS_MODE_MICRO"): 22,
        ("CS_ARCH_M68K", "0"): 23,
        ("CS_ARCH_M680X", "CS_MODE_M680X_6809"): 24,
        ("CS_ARCH_EVM", "0"): 25,
        ("CS_ARCH_BPF", "CS_MODE_LITTLE_ENDIAN+CS_MODE_BPF_CLASSIC"): 29,
        ("CS_ARCH_BPF", "CS_MODE_LITTLE_ENDIAN+CS_MODE_BPF_EXTENDED"): 30,
        ("CS_ARCH_BPF", "CS_MODE_BIG_ENDIAN+CS_MODE_BPF_CLASSIC"): 31,
        ("CS_ARCH_BPF", "CS_MODE_BIG_ENDIAN+CS_MODE_BPF_EXTENDED"): 32,
        ("CS_ARCH_RISCV", "CS_MODE_RISCV32"): 44,
        ("CS_ARCH_RISCV", "CS_MODE_RISCV64"): 45,
        ("CS_ARCH_TRICORE", "CS_MODE_TRICORE_110"): 47,
        ("CS_ARCH_TRICORE", "CS_MODE_TRICORE_120"): 48,
        ("CS_ARCH_TRICORE", "CS_MODE_TRICORE_130"): 49,
        ("CS_ARCH_TRICORE", "CS_MODE_TRICORE_131"): 50,
        ("CS_ARCH_TRICORE", "CS_MODE_TRICORE_160"): 51,
        ("CS_ARCH_TRICORE", "CS_MODE_TRICORE_161"): 52,
        ("CS_ARCH_TRICORE", "CS_MODE_TRICORE_162"): 53,
    }

    #if not option in ('', 'None'):
    #    print archs[arch], modes[mode], options[option]

    for line in lines[1:]:
        # ignore all the input lines having # in front.
        if line.startswith('#'):
            continue
        if line.startswith('// '):
            line=line[3:]
        #print("Check %s" %line)
        code = line.split(' = ')[0]
        if len(code) < 2:
            continue
        if code.find('//') >= 0:
            continue
        hex_code = code.replace('0x', '')
        hex_code = hex_code.replace(',', '')
        hex_code = hex_code.replace(' ', '')
        try:
            hex_data = hex_code.strip().decode('hex')
        except:
            print "skipping", hex_code
        fout = open("fuzz/corpus/%s_%s" % (os.path.basename(fname), hex_code), 'w')
        if (arch, mode) not in mc_modes:
            print "fail", arch, mode
        fout.write(unichr(mc_modes[(arch, mode)]))
        fout.write(hex_data)
        fout.close()


if __name__ == '__main__':
    if len(sys.argv) == 1:
        fnames = sys.stdin.readlines()
        for fname in fnames:
            test_file(fname.strip())
    else:
        #print("Usage: ./test_mc.py <input-file.s.cs>")
        test_file(sys.argv[1])


#!/usr/bin/env python3
# Test tool to compare Capstone output with llvm-mc. By Nguyen Anh Quynh, 2014
import sys
import os
from capstone import *
from pathlib import Path
import codecs


def test_file(fname):
    print("Test %s" % fname)
    fpath = Path(fname) if isinstance(fname, str) else fname
    if fpath.is_dir():
        if fpath.exists() is False:
            return
        for f in fpath.iterdir():
            test_file(f)
        return

    with fpath.open() as f:
        lines = f.readlines()

    if not lines[0].startswith('# '):
        print("ERROR: decoding information is missing")
        return

    # skip '# ' at the front, then split line to get out hexcode
    # Note: option can be '', or 'None'
    # print lines[0]
    # print lines[0][2:].split(', ')
    (arch, mode, option) = lines[0][2:].split(', ')
    mode = mode.replace(' ', '')
    option = option.strip()

    archs = {
        "CS_ARCH_ARM": CS_ARCH_ARM,
        "CS_ARCH_AARCH64": CS_ARCH_AARCH64,
        "CS_ARCH_MIPS": CS_ARCH_MIPS,
        "CS_ARCH_PPC": CS_ARCH_PPC,
        "CS_ARCH_SPARC": CS_ARCH_SPARC,
        "CS_ARCH_SYSTEMZ": CS_ARCH_SYSTEMZ,
        "CS_ARCH_X86": CS_ARCH_X86,
        "CS_ARCH_XCORE": CS_ARCH_XCORE,
        "CS_ARCH_RISCV": CS_ARCH_RISCV,
        "CS_ARCH_TRICORE": CS_ARCH_TRICORE,
        "CS_ARCH_ALPHA": CS_ARCH_ALPHA,
        "CS_ARCH_HPPA": CS_ARCH_HPPA,
        "CS_ARCH_ARC": CS_ARCH_ARC,
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
        "CS_MODE_ARM+CS_MODE_V8": CS_MODE_ARM + CS_MODE_V8,
        "CS_MODE_THUMB+CS_MODE_V8": CS_MODE_THUMB + CS_MODE_V8,
        "CS_MODE_THUMB+CS_MODE_MCLASS": CS_MODE_THUMB + CS_MODE_MCLASS,
        "CS_MODE_THUMB+CS_MODE_V8+CS_MODE_MCLASS": CS_MODE_THUMB+CS_MODE_V8+CS_MODE_MCLASS,
        "CS_MODE_LITTLE_ENDIAN": CS_MODE_LITTLE_ENDIAN,
        "CS_MODE_BIG_ENDIAN": CS_MODE_BIG_ENDIAN,
        "CS_MODE_64+CS_MODE_LITTLE_ENDIAN": CS_MODE_64 + CS_MODE_LITTLE_ENDIAN,
        "CS_MODE_64+CS_MODE_BIG_ENDIAN": CS_MODE_64 + CS_MODE_BIG_ENDIAN,
        "CS_MODE_MIPS32+CS_MODE_MICRO": CS_MODE_MIPS32 + CS_MODE_MICRO,
        "CS_MODE_MIPS32+CS_MODE_MICRO+CS_MODE_BIG_ENDIAN": CS_MODE_MIPS32 + CS_MODE_MICRO + CS_MODE_BIG_ENDIAN,
        "CS_MODE_MIPS32+CS_MODE_BIG_ENDIAN+CS_MODE_MICRO": CS_MODE_MIPS32 + CS_MODE_MICRO + CS_MODE_BIG_ENDIAN,
        "CS_MODE_BIG_ENDIAN+CS_MODE_V9": CS_MODE_BIG_ENDIAN + CS_MODE_V9,
        "CS_MODE_MIPS32+CS_MODE_BIG_ENDIAN": CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN,
        "CS_MODE_MIPS32+CS_MODE_LITTLE_ENDIAN": CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN,
        "CS_MODE_MIPS64+CS_MODE_LITTLE_ENDIAN": CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN,
        "CS_MODE_MIPS64+CS_MODE_BIG_ENDIAN": CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN,
        "CS_MODE_RISCV32": CS_MODE_RISCV32,
        "CS_MODE_RISCV64": CS_MODE_RISCV64,
        "CS_MODE_TRICORE_110": CS_MODE_TRICORE_110,
        "CS_MODE_TRICORE_120": CS_MODE_TRICORE_120,
        "CS_MODE_TRICORE_130": CS_MODE_TRICORE_130,
        "CS_MODE_TRICORE_131": CS_MODE_TRICORE_131,
        "CS_MODE_TRICORE_160": CS_MODE_TRICORE_160,
        "CS_MODE_TRICORE_161": CS_MODE_TRICORE_161,
        "CS_MODE_TRICORE_162": CS_MODE_TRICORE_162,
        "CS_MODE_TRICORE_180": CS_MODE_TRICORE_180,
        "CS_MODE_BIG_ENDIAN+CS_MODE_QPX": CS_MODE_BIG_ENDIAN+CS_MODE_QPX,
        "CS_MODE_HPPA_11": CS_MODE_HPPA_11,
        "CS_MODE_HPPA_20": CS_MODE_HPPA_20,
        "CS_MODE_HPPA_20W": CS_MODE_HPPA_20W,
    }

    mc_modes = {
        ("CS_ARCH_X86", "CS_MODE_32"): 0,
        ("CS_ARCH_X86", "CS_MODE_64"): 1,
        ("CS_ARCH_ARM", "CS_MODE_ARM"): 2,
        ("CS_ARCH_ARM", "CS_MODE_THUMB"): 3,
        ("CS_ARCH_ARM", "CS_MODE_ARM+CS_MODE_V8"): 4,
        ("CS_ARCH_ARM", "CS_MODE_THUMB+CS_MODE_V8"): 5,
        ("CS_ARCH_ARM", "CS_MODE_THUMB+CS_MODE_MCLASS"): 6,
        ("CS_ARCH_ARM", "CS_MODE_THUMB+CS_MODE_V8+CS_MODE_MCLASS"): 7,
        ("CS_ARCH_AARCH64", "0"): 8,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32+CS_MODE_BIG_ENDIAN"): 9,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32+CS_MODE_MICRO"): 10,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS64"): 11,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32"): 12,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS64+CS_MODE_BIG_ENDIAN"): 13,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32+CS_MODE_MICRO+CS_MODE_BIG_ENDIAN"): 14,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32+CS_MODE_BIG_ENDIAN+CS_MODE_MICRO"): 14,
        ("CS_ARCH_PPC", "CS_MODE_BIG_ENDIAN"): 15,
        ("CS_ARCH_SPARC", "CS_MODE_BIG_ENDIAN"): 16,
        ("CS_ARCH_SPARC", "CS_MODE_BIG_ENDIAN+CS_MODE_V9"): 17,
        ("CS_ARCH_SYSTEMZ", "CS_MODE_BIG_ENDIAN"): 18,
        ("CS_ARCH_XCORE", "0"): 19,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32R6+CS_MODE_BIG_ENDIAN"): 20,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32R6+CS_MODE_MICRO+CS_MODE_BIG_ENDIAN"): 21,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32R6"): 22,
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32R6+CS_MODE_MICRO"): 23,
        ("CS_ARCH_M68K", "0"): 24,
        ("CS_ARCH_M680X", "CS_MODE_M680X_6809"): 25,
        ("CS_ARCH_EVM", "0"): 26,
        ("CS_ARCH_BPF", "CS_MODE_LITTLE_ENDIAN+CS_MODE_BPF_CLASSIC"): 30,
        ("CS_ARCH_BPF", "CS_MODE_LITTLE_ENDIAN+CS_MODE_BPF_EXTENDED"): 31,
        ("CS_ARCH_BPF", "CS_MODE_BIG_ENDIAN+CS_MODE_BPF_CLASSIC"): 32,
        ("CS_ARCH_BPF", "CS_MODE_BIG_ENDIAN+CS_MODE_BPF_EXTENDED"): 33,
        ("CS_ARCH_RISCV", "CS_MODE_RISCV32"): 45,
        ("CS_ARCH_RISCV", "CS_MODE_RISCV64"): 46,
        ("CS_ARCH_TRICORE", "CS_MODE_TRICORE_110"): 47,
        ("CS_ARCH_TRICORE", "CS_MODE_TRICORE_120"): 48,
        ("CS_ARCH_TRICORE", "CS_MODE_TRICORE_130"): 49,
        ("CS_ARCH_TRICORE", "CS_MODE_TRICORE_131"): 50,
        ("CS_ARCH_TRICORE", "CS_MODE_TRICORE_160"): 51,
        ("CS_ARCH_TRICORE", "CS_MODE_TRICORE_161"): 52,
        ("CS_ARCH_TRICORE", "CS_MODE_TRICORE_162"): 53,
        ("CS_ARCH_PPC", "CS_MODE_BIG_ENDIAN+CS_MODE_QPX"): 54,
        ("CS_ARCH_ALPHA", "CS_MODE_LITTLE_ENDIAN"): 55,
        ("CS_ARCH_ALPHA", "CS_MODE_BIG_ENDIAN"): 56,
        ("CS_ARCH_HPPA", "CS_MODE_HPPA_11+CS_MODE_BIG_ENDIAN"): 57,
        ("CS_ARCH_HPPA", "CS_MODE_HPPA_20+CS_MODE_BIG_ENDIAN"): 58,
        ("CS_ARCH_TRICORE", "CS_MODE_TRICORE_180"): 59,
        ("CS_ARCH_ARC", "CS_MODE_LITTLE_ENDIAN"): 60,
    }

    # if not option in ('', 'None'):
    #    print archs[arch], modes[mode], options[option]

    for line in lines[1:]:
        # ignore all the input lines having # in front.
        if line.startswith('#'):
            continue
        if line.startswith('// '):
            line = line[3:]
        # print("Check %s" %line)
        code = line.split(' = ')[0]
        if len(code) < 2:
            continue
        if code.find('//') >= 0:
            continue
        hex_code = code.replace('0x', '').replace(',', '').replace(' ', '').strip()
        try:
            hex_data = bytes.fromhex(hex_code)
            fpath = Path("fuzz/corpus/%s_%s" % (os.path.basename(fname), hex_code))
            if fpath.parent.exists() is False:
                fpath.parent.mkdir(parents=True)
            with fpath.open('wb') as fout:
                if (arch, mode) not in mc_modes:
                    print("fail", arch, mode)
                if mode == "None":
                    mode = "0"
                fout.write(mc_modes[(arch, mode)].to_bytes(1, 'little'))
                fout.write(hex_data)
        except Exception as e:
            print(f"skipping: {hex_code} with: {e}")
            continue


if __name__ == '__main__':
    if len(sys.argv) == 1:
        fnames = sys.stdin.readlines()
        for fname in fnames:
            test_file(fname.strip())
    else:
        # print("Usage: ./test_mc.py <input-file.s.cs>")
        test_file(sys.argv[1])

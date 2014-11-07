#!/usr/bin/python
# Test tool to compare Capstone output with llvm-mc. By Nguyen Anh Quynh, 2014
import array, os.path, sys
from subprocess import Popen, PIPE, STDOUT
from capstone import *

def run_mc(arch, hexcode, option, syntax=None):
    def normalize(text):
        # remove tabs
        items = text.split()
        text = ' '.join(items)
         # remove comment after #
        if arch == CS_ARCH_X86:
            i = text.find('# ')
            if i != -1:
                return text[:i].lower()
        return text.lower()

    #print("Trying to decode: %s" %hexcode)
    if syntax:
        if arch == CS_ARCH_MIPS:
            p = Popen(['llvm-mc', '-disassemble', '-print-imm-hex', '-mattr=+msa', syntax] + option, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        else:
            p = Popen(['llvm-mc', '-disassemble', '-print-imm-hex', syntax] + option, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
    else:
        if arch == CS_ARCH_MIPS:
            p = Popen(['llvm-mc', '-disassemble', '-print-imm-hex', '-mattr=+msa'] + option, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        else:
            p = Popen(['llvm-mc', '-disassemble', '-print-imm-hex'] + option, stdout=PIPE, stdin=PIPE, stderr=STDOUT)
    output = p.communicate(input=hexcode)[0]
    lines = output.split('\n')
    #print lines
    if 'invalid' in lines[0]:
        #print 'invalid ----'
        return 'FAILED to disassemble'
    else:
        #print 'OK:', lines[1]
        return normalize(lines[1].strip())

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
    }
    
    modes = {
        "CS_MODE_16": CS_MODE_16,
        "CS_MODE_32": CS_MODE_32,
        "CS_MODE_64": CS_MODE_64,
        "0": CS_MODE_ARM,
        "CS_MODE_ARM": CS_MODE_ARM,
        "CS_MODE_THUMB": CS_MODE_THUMB,
        "CS_MODE_LITTLE_ENDIAN": CS_MODE_LITTLE_ENDIAN,
        "CS_MODE_BIG_ENDIAN": CS_MODE_BIG_ENDIAN,
        "CS_MODE_32+CS_MODE_BIG_ENDIAN": CS_MODE_32+CS_MODE_BIG_ENDIAN,
        "CS_MODE_32+CS_MODE_LITTLE_ENDIAN": CS_MODE_32+CS_MODE_LITTLE_ENDIAN,
        "CS_MODE_64+CS_MODE_LITTLE_ENDIAN": CS_MODE_64+CS_MODE_LITTLE_ENDIAN,
        "CS_MODE_64+CS_MODE_BIG_ENDIAN": CS_MODE_64+CS_MODE_BIG_ENDIAN,
        "CS_MODE_32+CS_MODE_MICRO": CS_MODE_32+CS_MODE_MICRO,
        "CS_MODE_32+CS_MODE_MICRO+CS_MODE_BIG_ENDIAN": CS_MODE_32+CS_MODE_MICRO+CS_MODE_BIG_ENDIAN,
        "CS_MODE_32+CS_MODE_BIG_ENDIAN+CS_MODE_MICRO": CS_MODE_32+CS_MODE_MICRO+CS_MODE_BIG_ENDIAN,
        "CS_MODE_BIG_ENDIAN+CS_MODE_V9": CS_MODE_BIG_ENDIAN + CS_MODE_V9,
    }
    
    options = {
        "CS_OPT_SYNTAX_ATT": CS_OPT_SYNTAX_ATT,
        "CS_OPT_SYNTAX_NOREGNAME": CS_OPT_SYNTAX_NOREGNAME,
    }

    mc_modes = {
        ("CS_ARCH_X86", "CS_MODE_32"): ['-triple=i386'],
        ("CS_ARCH_X86", "CS_MODE_64"): ['-triple=x86_64'],
        ("CS_ARCH_ARM", "CS_MODE_ARM"): ['-triple=armv7'],
        ("CS_ARCH_ARM", "CS_MODE_THUMB"): ['-triple=armv7'],
        ("CS_ARCH_ARM64", "0"): ['-triple=aarch64'],
        ("CS_ARCH_MIPS", "CS_MODE_32+CS_MODE_BIG_ENDIAN"): ['-triple=mips'],
        ("CS_ARCH_MIPS", "CS_MODE_32+CS_MODE_MICRO"): ['-triple=mipsel', '-mattr=+micromips'],
        ("CS_ARCH_MIPS", "CS_MODE_64"): ['-triple=mips64el'],
        ("CS_ARCH_MIPS", "CS_MODE_32"): ['-triple=mipsel'],
        ("CS_ARCH_MIPS", "CS_MODE_64+CS_MODE_BIG_ENDIAN"): ['-triple=mips64'],
        ("CS_ARCH_MIPS", "CS_MODE_32+CS_MODE_MICRO+CS_MODE_BIG_ENDIAN"): ['-triple=mips', '-mattr=+micromips'],
        ("CS_ARCH_MIPS", "CS_MODE_32+CS_MODE_BIG_ENDIAN+CS_MODE_MICRO"): ['-triple=mips', '-mattr=+micromips'],
        ("CS_ARCH_PPC", "CS_MODE_BIG_ENDIAN"): ['-triple=powerpc64'],
        ('CS_ARCH_SPARC', 'CS_MODE_BIG_ENDIAN'): ['-triple=sparc'],
        ('CS_ARCH_SPARC', 'CS_MODE_BIG_ENDIAN+CS_MODE_V9'): ['-triple=sparcv9'],
        ('CS_ARCH_SYSZ', '0'): ['-triple=s390x'],
    }

    #if not option in ('', 'None'):
    #    print archs[arch], modes[mode], options[option]
    
    #print(arch, mode, option)
    md = Cs(archs[arch], modes[mode])

    mc_option = None
    if arch == 'CS_ARCH_X86':
        # tell llvm-mc to use Intel syntax
        mc_option = '-output-asm-variant=1'

    if arch == 'CS_ARCH_ARM':
        md.syntax = CS_OPT_SYNTAX_NOREGNAME

    for line in lines[1:]:
        # ignore all the input lines having # in front.
        if line.startswith('#'):
            continue
        #print("Check %s" %line)
        code = line.split(' = ')[0]
        hex_code = code.replace('0x', '')
        hex_code = hex_code.replace(',', '')
        hex_data = hex_code.decode('hex')
        #hex_bytes = array.array('B', hex_data)

        x = list(md.disasm(hex_data, 0))
        if len(x) > 0:
            if x[0].op_str != '':
                cs_output = "%s %s" %(x[0].mnemonic, x[0].op_str)
            else:
                cs_output = x[0].mnemonic
        else:
            cs_output = 'FAILED to disassemble'

        mc_output = run_mc(archs[arch], code, mc_modes[(arch, mode)], mc_option)
        if (cs_output != mc_output):
            print("Mismatch: %s" %code)
            print("\tMC = %s" %mc_output)
            print("\tCS = %s" %cs_output)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        fnames = sys.stdin.readlines()
        for fname in fnames:
            test_file(fname.strip())
    else:
        #print("Usage: ./test_mc.py <input-file.s.cs>")
        test_file(sys.argv[1])


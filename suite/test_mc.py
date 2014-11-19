#!/usr/bin/python
# Test tool to compare Capstone output with llvm-mc. By Nguyen Anh Quynh, 2014
import array, os.path, sys
from subprocess import Popen, PIPE, STDOUT
from capstone import *


# convert all hex numbers to decimal numbers in a text
def normalize_hex(a):
    while(True):
        i = a.find('0x')
        if i == -1: # no more hex number
            break
        hexnum = '0x'
        for c in a[i + 2:]:
            if c in '0123456789abcdefABCDEF':
                hexnum += c
            else:
                break
        num = int(hexnum, 16)
        a = a.replace(hexnum, str(num))
    return a


def run_mc(arch, hexcode, option, syntax=None):
    def normalize(text):
        # remove tabs
        text = text.lower()
        items = text.split()
        text = ' '.join(items)
        if arch == CS_ARCH_X86:
            # remove comment after #
            i = text.find('# ')
            if i != -1:
                return text[:i].strip()
        if arch == CS_ARCH_ARM64:
            # remove comment after #
            i = text.find('// ')
            if i != -1:
                return text[:i].strip()
        # remove some redundant spaces
        text = text.replace('{ ', '{')
        text = text.replace(' }', '}')
        return text.strip()

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
        return 'FAILED to disassemble (MC)'
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
    }
    
    options = {
        "CS_OPT_SYNTAX_ATT": CS_OPT_SYNTAX_ATT,
        "CS_OPT_SYNTAX_NOREGNAME": CS_OPT_SYNTAX_NOREGNAME,
    }

    mc_modes = {
        ("CS_ARCH_X86", "CS_MODE_32"): ['-triple=i386'],
        ("CS_ARCH_X86", "CS_MODE_64"): ['-triple=x86_64'],
        ("CS_ARCH_ARM", "CS_MODE_ARM"): ['-triple=armv7'],
        ("CS_ARCH_ARM", "CS_MODE_THUMB"): ['-triple=thumbv7'],
        ("CS_ARCH_ARM", "CS_MODE_ARM+CS_MODE_V8"): ['-triple=armv8'],
        ("CS_ARCH_ARM", "CS_MODE_THUMB+CS_MODE_V8"): ['-triple=thumbv8'],
        ("CS_ARCH_ARM", "CS_MODE_THUMB+CS_MODE_MCLASS"): ['-triple=thumbv7m'],
        ("CS_ARCH_ARM64", "0"): ['-triple=aarch64'],
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32+CS_MODE_BIG_ENDIAN"): ['-triple=mips'],
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32+CS_MODE_MICRO"): ['-triple=mipsel', '-mattr=+micromips'],
        ("CS_ARCH_MIPS", "CS_MODE_MIPS64"): ['-triple=mips64el'],
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32"): ['-triple=mipsel'],
        ("CS_ARCH_MIPS", "CS_MODE_MIPS64+CS_MODE_BIG_ENDIAN"): ['-triple=mips64'],
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32+CS_MODE_MICRO+CS_MODE_BIG_ENDIAN"): ['-triple=mips', '-mattr=+micromips'],
        ("CS_ARCH_MIPS", "CS_MODE_MIPS32+CS_MODE_BIG_ENDIAN+CS_MODE_MICRO"): ['-triple=mips', '-mattr=+micromips'],
        ("CS_ARCH_PPC", "CS_MODE_BIG_ENDIAN"): ['-triple=powerpc64'],
        ('CS_ARCH_SPARC', 'CS_MODE_BIG_ENDIAN'): ['-triple=sparc'],
        ('CS_ARCH_SPARC', 'CS_MODE_BIG_ENDIAN+CS_MODE_V9'): ['-triple=sparcv9'],
        ('CS_ARCH_SYSZ', '0'): ['-triple=s390x', '-mcpu=z196'],
    }

    #if not option in ('', 'None'):
    #    print archs[arch], modes[mode], options[option]
    
    #print(arch, mode, option)
    md = Cs(archs[arch], modes[mode])

    mc_option = None
    if arch == 'CS_ARCH_X86':
        # tell llvm-mc to use Intel syntax
        mc_option = '-output-asm-variant=1'

    if arch == 'CS_ARCH_ARM' or arch == 'CS_ARCH_PPC' :
        md.syntax = CS_OPT_SYNTAX_NOREGNAME

    if fname.endswith('3DNow.s.cs'):
        md.syntax = CS_OPT_SYNTAX_ATT

    for line in lines[1:]:
        # ignore all the input lines having # in front.
        if line.startswith('#'):
            continue
        #print("Check %s" %line)
        code = line.split(' = ')[0]
        asm  = ''.join(line.split(' = ')[1:])
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

        cs_output2 = normalize_hex(cs_output)
        cs_output2 = cs_output2.replace(' ', '')

        if arch == 'CS_ARCH_MIPS':
            # normalize register alias names
            cs_output2 = cs_output2.replace('$at', '$1')
            cs_output2 = cs_output2.replace('$v0', '$2')
            cs_output2 = cs_output2.replace('$v1', '$3')

            cs_output2 = cs_output2.replace('$a0', '$4')
            cs_output2 = cs_output2.replace('$a1', '$5')
            cs_output2 = cs_output2.replace('$a2', '$6')
            cs_output2 = cs_output2.replace('$a3', '$7')

            cs_output2 = cs_output2.replace('$t0', '$8')
            cs_output2 = cs_output2.replace('$t1', '$9')
            cs_output2 = cs_output2.replace('$t2', '$10')
            cs_output2 = cs_output2.replace('$t3', '$11')
            cs_output2 = cs_output2.replace('$t4', '$12')
            cs_output2 = cs_output2.replace('$t5', '$13')
            cs_output2 = cs_output2.replace('$t6', '$14')
            cs_output2 = cs_output2.replace('$t7', '$15')
            cs_output2 = cs_output2.replace('$t8', '$24')
            cs_output2 = cs_output2.replace('$t9', '$25')

            cs_output2 = cs_output2.replace('$s0', '$16')
            cs_output2 = cs_output2.replace('$s1', '$17')
            cs_output2 = cs_output2.replace('$s2', '$18')
            cs_output2 = cs_output2.replace('$s3', '$19')
            cs_output2 = cs_output2.replace('$s4', '$20')
            cs_output2 = cs_output2.replace('$s5', '$21')
            cs_output2 = cs_output2.replace('$s6', '$22')
            cs_output2 = cs_output2.replace('$s7', '$23')

            cs_output2 = cs_output2.replace('$k0', '$26')
            cs_output2 = cs_output2.replace('$k1', '$27')

        #print("Running MC ...")
        if fname.endswith('thumb-fp-armv8.s.cs'):
            mc_output = run_mc(archs[arch], code, ['-triple=thumbv8'], mc_option)
        elif fname.endswith('mips64-alu-instructions.s.cs'):
            mc_output = run_mc(archs[arch], code, ['-triple=mips64el', '-mcpu=mips64r2'], mc_option)
        else:
            mc_output = run_mc(archs[arch], code, mc_modes[(arch, mode)], mc_option)
        mc_output2 = normalize_hex(mc_output)

        if arch == 'CS_ARCH_MIPS':
            mc_output2 = mc_output2.replace(' 0(', '(')

        if arch == 'CS_ARCH_PPC':
            mc_output2 = mc_output2.replace('.+', '')
            mc_output2 = mc_output2.replace('.', '')
            mc_output2 = mc_output2.replace(' 0(', '(')

        mc_output2 = mc_output2.replace(' ', '')
        mc_output2 = mc_output2.replace('opaque', '')


        if (cs_output2 != mc_output2):
            asm = asm.replace(' ', '').strip().lower()
            if asm != cs_output2:
                print("Mismatch: %s" %line.strip())
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


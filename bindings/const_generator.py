# Capstone Disassembler Engine
# By Dang Hoang Vu, 2013
from __future__ import print_function
import sys, re

INCL_DIR = '../include/capstone/'

include = [ 'arm.h', 'arm64.h', 'm68k.h', 'mips.h', 'x86.h', 'ppc.h', 'sparc.h', 'systemz.h', 'xcore.h', 'tms320c64x.h', 'm680x.h', 'evm.h', 'mos65xx.h', 'wasm.h', 'bpf.h' ,'riscv.h' ]

template = {
    'java': {
            'header': "// For Capstone Engine. AUTO-GENERATED FILE, DO NOT EDIT\npackage capstone;\n\npublic class %s_const {\n",
            'footer': "}",
            'line_format': '\tpublic static final int %s = %s;\n',
            'out_file': './java/capstone/%s_const.java',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'Arm',
            'arm64.h': 'Arm64',
            'm68k.h': 'M68k',
            'mips.h': 'Mips',
            'x86.h': 'X86',
            'ppc.h': 'Ppc',
            'sparc.h': 'Sparc',
            'systemz.h': 'Sysz',
            'xcore.h': 'Xcore',
            'tms320c64x.h': 'TMS320C64x',
            'm680x.h': 'M680x',
            'evm.h': 'Evm',
            'wasm.h': 'Wasm',
            'comment_open': '\t//',
            'comment_close': '',
        },
    'python': {
            'header': "# For Capstone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.py]\n",
            'footer': "",
            'line_format': '%s = %s\n',
            'out_file': './python/capstone/%s_const.py',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'm68k.h': 'm68k',
            'mips.h': 'mips',
            'x86.h': 'x86',
            'ppc.h': 'ppc',
            'sparc.h': 'sparc',
            'systemz.h': 'sysz',
            'xcore.h': 'xcore',
            'tms320c64x.h': 'tms320c64x',
            'm680x.h': 'm680x',
            'evm.h': 'evm',
            'wasm.h': 'wasm',
            'mos65xx.h': 'mos65xx',
            'bpf.h': 'bpf',
            'riscv.h': 'riscv',
            'comment_open': '#',
            'comment_close': '',
        },
    'ocaml': {
            'header': "(* For Capstone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.ml] *)\n",
            'footer': "",
            'line_format': 'let _%s = %s;;\n',
            'out_file': './ocaml/%s_const.ml',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'arm',
            'arm64.h': 'arm64',
            'mips.h': 'mips',
            'm68k.h': 'm68k',
            'x86.h': 'x86',
            'ppc.h': 'ppc',
            'sparc.h': 'sparc',
            'systemz.h': 'sysz',
            'xcore.h': 'xcore',
            'tms320c64x.h': 'tms320c64x',
            'm680x.h': 'm680x',
            'evm.h': 'evm',
            'wasm.h': 'wasm',
            'comment_open': '(*',
            'comment_close': ' *)',
        },
}

# markup for comments to be added to autogen files
MARKUP = '//>'

def gen(lang):
    global include, INCL_DIR
    print('Generating bindings for', lang)
    templ = template[lang]
    print('Generating bindings for', lang)
    for target in include:
        if target not in templ:
            print("Warning: No binding found for %s" % target)
            continue
        prefix = templ[target]
        outfile = open(templ['out_file'] %(prefix), 'wb')   # open as binary prevents windows newlines
        outfile.write((templ['header'] % (prefix)).encode("utf-8"))

        lines = open(INCL_DIR + target).readlines()

        count = 0
        for line in lines:
            line = line.strip()

            if line.startswith(MARKUP):  # markup for comments
                outfile.write(("\n%s%s%s\n" %(templ['comment_open'], \
                                              line.replace(MARKUP, ''), \
                                              templ['comment_close']) ).encode("utf-8"))
                continue

            if line == '' or line.startswith('//'):
                continue

            if line.startswith('#define '):
                line = line[8:]     #cut off define
                xline = re.split('\s+', line, 1)     #split to at most 2 express
                if len(xline) != 2:
                    continue
                if '(' in xline[0] or ')' in xline[0]:      #does it look like a function
                    continue
                xline.insert(1, '=')            # insert an = so the expression below can parse it
                line = ' '.join(xline)

            if not line.startswith(prefix.upper()):
                continue

            tmp = line.strip().split(',')
            for t in tmp:
                t = t.strip()
                if not t or t.startswith('//'): continue
                # hacky: remove type cast (uint64_t)
                t = t.replace('(uint64_t)', '')
                t = re.sub(r'\((\d+)ULL << (\d+)\)', r'\1 << \2', t)    # (1ULL<<1) to 1 << 1
                f = re.split('\s+', t)

                if f[0].startswith(prefix.upper()):
                    if len(f) > 1 and f[1] not in ('//', '///<', '='):
                        print("Error: Unable to convert %s" % f)
                        continue
                    elif len(f) > 1 and f[1] == '=':
                        rhs = ''.join(f[2:])
                    else:
                        rhs = str(count)
                        count += 1

                    try:
                        count = int(rhs) + 1
                        if (count == 1):
                            outfile.write(("\n").encode("utf-8"))
                    except ValueError:
                        if lang == 'ocaml':
                            # ocaml uses lsl for '<<', lor for '|'
                            rhs = rhs.replace('<<', ' lsl ')
                            rhs = rhs.replace('|', ' lor ')
                            # ocaml variable has _ as prefix
                            if rhs[0].isalpha():
                                rhs = '_' + rhs

                    outfile.write((templ['line_format'] %(f[0].strip(), rhs)).encode("utf-8"))

        outfile.write((templ['footer']).encode("utf-8"))
        outfile.close()

def main():
    try:
        if sys.argv[1] == 'all':
            for key in template.keys():
                gen(key)
        else:
            gen(sys.argv[1])
    except:
        raise RuntimeError("Unsupported binding %s" % sys.argv[1])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:", sys.argv[0], " <bindings: java|python|ocaml|all>")
        sys.exit(1)
    main()

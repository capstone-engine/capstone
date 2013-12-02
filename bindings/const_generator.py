# Capstone Disassembler Engine
# By Dang Hoang Vu, 2013

import sys, re

INCL_DIR = '../include'

include = [
    ('/arm.h', 'ARM_'),
    ('/arm64.h', 'ARM64_'),
    ('/x86.h', 'X86_'),
    ('/mips.h', 'MIPS_'),
]

template = {
    'java': {
            'header': "// For Capstone Engine. AUTO-GENERATED FILE, DO NOT EDIT\npackage capstone;\n\npublic class %sconst {\n",
            'footer': "}",
            'line_format': '\tpublic static final int %s = %s;\n',
            'out_file': './java/capstone/%sconst.java',
        },
    'python': {
            'header': "# For Capstone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%sconst.py]\n",
            'footer': "",
            'line_format': '%s = %s\n',
            'out_file': './python/capstone/%sconst.py',
        }
}

def gen(templ):
    global include, INCL_DIR
    for target in include:
        prefix = target[1];
        outfile = open(templ['out_file'] %(prefix.capitalize()), 'w')
        outfile.write(templ['header'] % (prefix.capitalize()))

        lines = open(INCL_DIR + target[0]).readlines()

        count = 0
        for line in lines:
            line = line.strip()
            if line == '' or line.startswith('//'):
                continue
            if not line.startswith(prefix):
                continue

            tmp = line.strip().split(',')
            for t in tmp:
                t = t.strip()
                if not t or t.startswith('//'): continue
                f = re.split('\s+', t)

                if f[0].startswith(prefix):
                    if len(f) > 1 and f[1] not in '//=':
                        print "Error: Unable to convert %s" % f
                        continue
                    elif len(f) > 1 and f[1] == '=':
                        rhs = f[2]
                    else:
                        rhs = str(count)
                        count += 1

                    if rhs == '0':
                        outfile.write("\n")
                        count = 1

                    outfile.write(templ['line_format'] %(f[0].strip(), rhs))

        outfile.write(templ['footer'])
        outfile.close()

def main():
    try:
        gen(template[sys.argv[1]])
    except:
        raise RuntimeError("Unsupported binding %s" % sys.argv[1])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage:", sys.argv[0], " <bindings: java|python>"
        sys.exit(1)
    main()

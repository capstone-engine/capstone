# Capstone Disassembler Engine
# By Dang Hoang Vu, 2013

import sys, re

INCL_DIR = '../include/'

include = [ 'arm.h', 'arm64.h', 'mips.h', 'x86.h', 'ppc.h' ]

template = {
    'java': {
            'header': "// For Capstone Engine. AUTO-GENERATED FILE, DO NOT EDIT\npackage capstone;\n\npublic class %s_const {\n",
            'footer': "}",
            'line_format': '\tpublic static final int %s = %s;\n',
            'out_file': './java/capstone/%s_const.java',
            # prefixes for constant filenames of all archs - case sensitive
            'arm.h': 'Arm',
            'arm64.h': 'Arm64',
            'mips.h': 'Mips',
            'x86.h': 'X86',
            'ppc.h': 'Ppc',
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
            'mips.h': 'mips',
            'x86.h': 'x86',
            'ppc.h': 'ppc',
            'comment_open': '#',
            'comment_close': '',
        }
}

# markup for comments to be added to autogen files
MARKUP = '//>'

def gen(templ):
    global include, INCL_DIR
    for target in include:
        prefix = templ[target]
        outfile = open(templ['out_file'] %(prefix), 'w')
        outfile.write(templ['header'] % (prefix))

        lines = open(INCL_DIR + target).readlines()

        count = 0
        for line in lines:
            line = line.strip()

            if line.startswith(MARKUP):  # markup for comments
                outfile.write("\n%s%s%s\n" %(templ['comment_open'], \
                            line.replace(MARKUP, ''), templ['comment_close']))
                continue

            if line == '' or line.startswith('//'):
                continue

            if not line.startswith(prefix.upper()):
                continue

            tmp = line.strip().split(',')
            for t in tmp:
                t = t.strip()
                if not t or t.startswith('//'): continue
                f = re.split('\s+', t)

                if f[0].startswith(prefix.upper()):
                    if len(f) > 1 and f[1] not in '//=':
                        print "Error: Unable to convert %s" % f
                        continue
                    elif len(f) > 1 and f[1] == '=':
                        rhs = ''.join(f[2:])
                    else:
                        rhs = str(count)
                        count += 1

                    try:
                        count = int(rhs) + 1
                        if (count == 1):
                            outfile.write("\n")
                    except ValueError:
                        pass

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

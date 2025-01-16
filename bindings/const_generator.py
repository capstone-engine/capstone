# Capstone Disassembler Engine
# By Dang Hoang Vu, 2013
from __future__ import print_function
import sys, re

INCL_DIR = '../include/capstone/'

include = [ 'arm.h', 'arm64.h', 'm68k.h', 'mips.h', 'x86.h', 'ppc.h', 'sparc.h', 'systemz.h', 'xcore.h', 'tms320c64x.h', 'm680x.h', 'evm.h', 'mos65xx.h', 'wasm.h', 'bpf.h' ,'riscv.h', 'sh.h', 'tricore.h' ]

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
            'header': "from . import CS_OP_INVALID, CS_OP_REG, CS_OP_IMM, CS_OP_MEM\n"
                      "# For Capstone Engine. AUTO-GENERATED FILE, DO NOT EDIT [%s_const.py]\n",
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
            'sh.h': 'sh',
            'tricore.h': ['TRICORE', 'TriCore'],
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
    # 'swift': {
    #         'header': "// For Capstone Engine. AUTO-GENERATED FILE, DO NOT EDIT (%s)\n\n",
    #         'footer': "",
    #         'enum_doc': '/// %s\n',
    #         'enum_header': 'public enum %s: %s {\n',
    #         'enum_default_type': 'UInt32',
    #         'enum_types': {
    #             'UInt16': r'^\w+Reg$',
    #             'UInt8': r'^\w+Grp$'
    #         },
    #         'option_set_header': 'public struct %s: OptionSet {\n    public typealias RawValue = %s\n    public let rawValue: RawValue\n    public init(rawValue: RawValue) { self.rawValue = rawValue }\n',
    #         'option_sets': {
    #             'X86Eflags': 'UInt64',
    #             'X86FpuFlags': 'UInt64',
    #             'SparcHint': 'UInt32',
    #             'M680xIdx': 'UInt8',
    #             'M680xOpFlags': 'UInt8',
    #         },
    #         'rename': {
    #             r'^M680X_(\w+_OP_IN_MNEM)$': r'M680X_OP_FLAGS_\1',
    #         },
    #         'option_format': '    public static let {option} = {type}(rawValue: {value})\n',
    #         'enum_extra_options': {
    #             # swift enum != OptionSet, so options must be specified
    #             'ArmSysreg': {
    #                 'spsrCx': 'spsrC + spsrX',
    #                 'spsrCs': 'spsrC + spsrS',
    #                 'spsrXs': 'spsrX + spsrS',
    #                 'spsrCxs': 'spsrC + spsrX + spsrS',
    #                 'spsrCf': 'spsrC + spsrF',
    #                 'spsrXf': 'spsrX + spsrF',
    #                 'spsrCxf': 'spsrC + spsrX + spsrF',
    #                 'spsrSf': 'spsrS + spsrF',
    #                 'spsrCsf': 'spsrC + spsrS + spsrF',
    #                 'spsrXsf': 'spsrX + spsrS + spsrF',
    #                 'spsrCxsf': 'spsrC + spsrX + spsrS + spsrF',
    #                 'cpsrCx': 'cpsrC + cpsrX',
    #                 'cpsrCs': 'cpsrC + cpsrS',
    #                 'cpsrXs': 'cpsrX + cpsrS',
    #                 'cpsrCxs': 'cpsrC + cpsrX + cpsrS',
    #                 'cpsrCf': 'cpsrC + cpsrF',
    #                 'cpsrXf': 'cpsrX + cpsrF',
    #                 'cpsrCxf': 'cpsrC + cpsrX + cpsrF',
    #                 'cpsrSf': 'cpsrS + cpsrF',
    #                 'cpsrCsf': 'cpsrC + cpsrS + cpsrF',
    #                 'cpsrXsf': 'cpsrX + cpsrS + cpsrF',
    #                 'cpsrCxsf': 'cpsrC + cpsrX + cpsrS + cpsrF',
    #             }
    #         },
    #         'enum_footer': '}\n\n',
    #         'doc_line_format': '    /// %s\n',
    #         'line_format': '    case %s = %s\n',
    #         'dup_line_format': '    public static let %s = %s\n',
    #         'out_file': './swift/Sources/Capstone/%sEnums.swift',
    #         'reserved_words': [
    #             'break', 'class', 'for', 'false', 'in', 'init', 'return', 'true'
    #         ],
    #         'reserved_word_format': '`%s`',
    #         # prefixes for constant filenames of all archs - case sensitive
    #         'arm.h': 'Arm',
    #         'arm64.h': 'Arm64',
    #         'm68k.h': 'M68k',
    #         'mips.h': 'Mips',
    #         'x86.h': 'X86',
    #         'ppc.h': 'Ppc',
    #         'sparc.h': 'Sparc',
    #         'systemz.h': 'Sysz',
    #         'xcore.h': 'Xcore',
    #         'tms320c64x.h': 'TMS320C64x',
    #         'm680x.h': 'M680x',
    #         'evm.h': 'Evm',
    #         'mos65xx.h': 'Mos65xx',
    #         'comment_open': '\t//',
    #         'comment_close': '',
    #     },
}

# markup for comments to be added to autogen files
MARKUP = '//>'

def camelize(name):
    parts = name.split('_')
    return parts[0].lower() + ''.join(map(str.capitalize, parts[1:]))

def pascalize(name):
    parts = name.split('_')
    return ''.join(map(str.capitalize, parts))

def pascalize_const(name):
    parts = name.split('_',2)
    match = re.match('^(CC|DISP|MOD|DIR|BCAST|RM|FLAGS|SIZE|BR_DISP_SIZE)_', parts[2])
    if match:
        parts = name.split('_', 2 + match.group(0).count('_'))
    item = camelize(parts[-1])
    if item[0].isdigit():
        item = parts[-2].lower() + item
    return (pascalize('_'.join(parts[0:-1])), item)

def enum_type(name, templ):
    for enum_type, pattern in templ['enum_types'].items():
        if re.match(pattern, name):
            return enum_type
    return templ['enum_default_type']

def write_enum_extra_options(outfile, templ, enum, enum_values):
    if 'enum_extra_options' in templ and enum in templ['enum_extra_options']:
        for name, value in templ['enum_extra_options'][enum].items():
            if type(value) is str:
                # evaluate within existing enum
                value = eval(value, None, enum_values)
            outfile.write((templ['line_format'] %(name, value)).encode("utf-8"))

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
        prefixs = []
        if isinstance(prefix, list):
            prefixs = prefix
            prefix = prefix[0].lower()

        outfile = open(templ['out_file'] %(prefix), 'wb')   # open as binary prevents windows newlines
        outfile.write((templ['header'] % (prefix)).encode("utf-8"))

        lines = open(INCL_DIR + target).readlines()
        enums = {}
        values = {}
        doc_lines = []

        count = 0
        for line in lines:
            line = line.strip()

            if line.startswith(MARKUP):  # markup for comments
                outfile.write(("\n%s%s%s\n" %(templ['comment_open'], \
                                              line.replace(MARKUP, ''), \
                                              templ['comment_close']) ).encode("utf-8"))
                continue

            if line.startswith('/// ') and 'enum_doc' in templ:
                doc_lines.append(line[4: ])
                continue
            elif line.startswith('}') or line.startswith('#'):
                doc_lines = []
                pass

            if line == '' or line.startswith('//'):
                continue

            if line.startswith('#define '):
                line = line[8:]     #cut off define
                xline = re.split(r'\s+', line, 1)     #split to at most 2 express
                if len(xline) != 2:
                    continue
                if '(' in xline[0] or ')' in xline[0]:      #does it look like a function
                    continue
                xline.insert(1, '=')            # insert an = so the expression below can parse it
                line = ' '.join(xline)

            def is_with_prefix(x):
                if prefixs:
                    return any(x.startswith(pre) for pre in prefixs)
                else:
                    return x.startswith(prefix.upper())

            if not is_with_prefix(line):
                continue

            tmp = line.strip().split(',')
            for t in tmp:
                t = t.strip()
                if not t or t.startswith('//'): continue
                # hacky: remove type cast (uint64_t)
                t = t.replace('(uint64_t)', '')
                t = re.sub(r'\((\d+)ULL << (\d+)\)', r'\1 << \2', t)    # (1ULL<<1) to 1 << 1
                f = re.split(r'\s+', t)

                if not is_with_prefix(f[0]):
                    continue

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

                if lang == 'swift':
                    value = eval(rhs, None, values)
                    exec('%s = %d' %(f[0].strip(), value), None, values)
                else:
                    value = rhs

                name = f[0].strip()

                if 'rename' in templ:
                    # constant renaming
                    for pattern, replacement in templ['rename'].items():
                        if re.match(pattern, name):
                            name = re.sub(pattern, replacement, name)
                            break


                if 'enum_header' in templ:
                    # separate constants by enums based on name
                    enum, name = pascalize_const(name)
                    if enum not in enums:
                        if len(enums) > 0:
                            write_enum_extra_options(outfile, templ, last_enum, enums[last_enum])
                            outfile.write((templ['enum_footer']).encode("utf-8"))
                        last_enum = enum

                        if 'enum_doc' in templ:
                            for doc_line in doc_lines:
                                outfile.write((templ['enum_doc'] %(doc_line)).encode("utf-8"))
                            doc_lines = []

                        if 'option_sets' in templ and enum in templ['option_sets']:
                            outfile.write((templ['option_set_header'] %(enum, templ['option_sets'][enum])).encode("utf-8"))
                        else:
                            outfile.write((templ['enum_header'] %(enum, enum_type(enum, templ))).encode("utf-8"))
                        enums[enum] = {}

                    if 'option_sets' in templ and enum in templ['option_sets']:
                        # option set format
                        line_format = templ['option_format'].format(option='%s',type=enum,value='%s')
                        if value == 0:
                            continue # skip empty option
                        # option set values need not be literals
                        value = rhs
                    elif 'dup_line_format' in templ and value in enums[enum].values():
                        # different format for duplicate values?
                        line_format = templ['dup_line_format']
                    else:
                        line_format = templ['line_format']
                    enums[enum][name] = value

                    # escape reserved words
                    if 'reserved_words' in templ and name in templ['reserved_words']:
                        name = templ['reserved_word_format'] %(name)

                    # print documentation?
                    if 'doc_line_format' in templ and '///<' in line:
                        doc = line.split('///<')[1].strip()
                        outfile.write((templ['doc_line_format'] %(doc)).encode("utf-8"))
                else:
                    line_format = templ['line_format']

                outfile.write((line_format %(name, value)).encode("utf-8"))

        if 'enum_footer' in templ:
            write_enum_extra_options(outfile, templ, enum, enums[enum])
            outfile.write((templ['enum_footer']).encode("utf-8"))
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

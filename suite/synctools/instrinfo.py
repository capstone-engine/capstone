#!/usr/bin/python
# convert LLVM GenInstrInfo.inc for Capstone disassembler.
# by Nguyen Anh Quynh, 2019

import sys

if len(sys.argv) == 1:
    print("Syntax: %s <GenInstrInfo.inc> <AsmMatcher.info>" %sys.argv[0])
    sys.exit(1)


# lib/Target/X86/X86GenAsmMatcher.inc
# static const MatchEntry MatchTable1[] = {
#  { 0 /* aaa */, X86::AAA, Convert_NoOperands, Feature_Not64BitMode, {  }, },

# return (arch, mnem)
def extract_insn(line):
    tmp = line.split(',')
    insn_raw = tmp[1].strip()
    insn_mnem = tmp[0].split(' ')[3]
    # X86 mov.s
    if '.' in insn_mnem:
        tmp = insn_mnem.split('.')
        insn_mnem = tmp[0]
    tmp = insn_raw.split('::')
    arch = tmp[0]
    # AArch64 -> ARM64
    if arch.upper() == 'AArch64':
        arch = 'ARM64'
    return (arch, insn_mnem)

# get (arch, first insn) from MatchTable
def get_first_insn(filename):
    f = open(filename)
    lines = f.readlines()
    f.close()
    count = 0
    for line in lines:
        line = line.strip()
    
        if len(line) == 0:
            continue
    
        # Intel syntax in Table1
        if 'MatchEntry MatchTable1[] = {' in line:
            count += 1
            #print(line.strip())
            continue
    
        if count == 1:
            arch, mnem = extract_insn(line)
            return (arch, mnem)

    return (None, None)


arch, first_insn = get_first_insn(sys.argv[2])
first_insn = first_insn.upper()
arch = arch.upper()
#print(arch, first_insn)

print("""
/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Instruction Enum Values and Descriptors                             *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM
""")

enum_count = 0
meet_insn = False

f = open(sys.argv[1])
lines = f.readlines()
f.close()

# 1st enum is register enum
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'enum {':
        enum_count += 1
        print(line.strip())
        continue

    line = line.strip()
    if enum_count == 1:
        if line == '};':
            # done with first enum
            break
        else:
            insn = None
            if meet_insn:
                # enum items
                insn = line
            elif line.startswith(first_insn):
                insn = line
                meet_insn = True
            if insn:
                print("\t%s_%s" %(arch, line))

print('};\n')

print("#endif // GET_INSTRINFO_ENUM")

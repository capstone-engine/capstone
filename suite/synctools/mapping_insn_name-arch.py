#!/usr/bin/python
# print list of instructions LLVM inc files, for Capstone disassembler.
# this will be put into capstone/<arch>.h
# by Nguyen Anh Quynh, 2019

import sys

if len(sys.argv) == 1:
    print("Syntax: %s <GenAsmMatcher.inc>" %sys.argv[0])
    sys.exit(1)

print("""/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* This is auto-gen data for Capstone disassembly engine (www.capstone-engine.org) */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
""")

# lib/Target/X86/X86GenAsmMatcher.inc
# static const MatchEntry MatchTable1[] = {
#  { 0 /* aaa */, X86::AAA, Convert_NoOperands, Feature_Not64BitMode, {  }, },

# extract insn from GenAsmMatcher Table
# return (arch, mnem, insn_id)
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
    if arch.upper() == 'AARCH64':
        arch = 'ARM64'
    return (arch, insn_mnem, tmp[1])



# extract all insn lines from GenAsmMatcher
# return arch, first_insn, insn_id_list
def extract_matcher(filename):
    f = open(filename)
    lines = f.readlines()
    f.close()

    match_count = 0
    mnem_list = []
    insn_id_list = {}
    arch = None
    first_insn = None

    pattern = None
    # first we try to find Table1, or Table0
    for line in lines:
        if 'MatchEntry MatchTable0[] = {' in line.strip():
            pattern = 'MatchEntry MatchTable0[] = {'
        elif 'MatchEntry MatchTable1[] = {' in line.strip():
            pattern = 'MatchEntry MatchTable1[] = {'
            # last pattern, done
            break

    # 1st enum is register enum
    for line in lines:
        line = line.rstrip()
    
        if len(line.strip()) == 0:
            continue
    
        if pattern in line.strip():
            match_count += 1
            #print(line.strip())
            continue
    
        line = line.strip()
        if match_count == 1:
            if line == '};':
                # done with first enum
                break
            else:
                _arch, mnem, insn_id = extract_insn(line)
                # skip pseudo instructions
                if not mnem.startswith('__'):
                    # PPC
                    if mnem.endswith('-') or mnem.endswith('+'):
                        mnem = mnem[:-1]

                    if not first_insn:
                        arch, first_insn = _arch, insn_id

                    if not insn_id in insn_id_list:
                        # save this
                        insn_id_list[insn_id] = mnem

                    if not mnem in mnem_list:
                        print('\t"%s", // %s_INS_%s,' %(mnem.lower(), arch, mnem.upper()))
                        mnem_list.append(mnem)

    #return arch, first_insn, insn_id_list
    return arch, first_insn, insn_id_list

# GenAsmMatcher.inc
#arch, first_insn, insn_id_list, match_lines = extract_matcher(sys.argv[1])
arch, first_insn, insn_id_list = extract_matcher(sys.argv[1])

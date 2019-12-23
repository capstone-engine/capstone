#!/usr/bin/python
# convert LLVM GenInstrInfo.inc for Capstone disassembler.
# by Nguyen Anh Quynh, 2019

import sys

if len(sys.argv) == 1:
    print("Syntax: %s <GenInstrInfo.inc> <arch>" %sys.argv[0])
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


#arch, first_insn = get_first_insn(sys.argv[2])
#first_insn = first_insn.upper()
#print(arch, first_insn)

arch = sys.argv[2].upper()

if arch.upper() == 'AARCH64':
    arch = 'AArch64'
elif arch.upper() == 'ARM64':
    arch = 'AArch64'

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
            # skip pseudo instructions
            if '__' in line or 'setjmp' in line or 'longjmp' in line or 'Pseudo' in line:
                pass
            else:
                print("\t%s_%s" %(arch, line))

print('};\n')

print("#endif // GET_INSTRINFO_ENUM")

if arch == 'ARM64':
    sys.exit(0)

print("")
print("#ifdef GET_INSTRINFO_MC_DESC")
print("#undef GET_INSTRINFO_MC_DESC")
print("")
print("#define nullptr 0")
print("")

in_insts = False

for line in lines:
    if line.strip() == '':
        continue

    line = line.rstrip()

    if 'static const MCOperandInfo ' in line:
        line2 = line.replace('::', '_')
        print(line2)

    elif 'Insts[] = {' in line:
        # extern const MCInstrDesc ARMInsts[] = {
        line2 = line.replace('extern const ', 'static const ')
        print("")
        print(line2)
        in_insts = True

    elif in_insts:
        if line == '};':
            print(line)
            break
        # { 0,  1,  1,  0,  0,  0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #0 = PHI
        # take 2nd & 10th entries 
        tmp = line.split(',')
        print("  { %s, %s }," %(tmp[1].strip(), tmp[9].strip()))


print("")
print("#endif // GET_INSTRINFO_MC_DESC")

#static const MCInstrDesc ARMInsts[] = {
#static MCOperandInfo OperandInfo2[] = { { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, };

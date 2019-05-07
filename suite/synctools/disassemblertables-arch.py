#!/usr/bin/python
# convert LLVM GenDisassemblerTables.inc for Capstone disassembler.
# this just adds a header
# by Nguyen Anh Quynh, 2019

import sys

if len(sys.argv) == 1:
    print("Syntax: %s <GenDisassemblerTables.inc> <arch>" %sys.argv[0])
    sys.exit(1)

f = open(sys.argv[1])
lines = f.readlines()
f.close()

print("/* Capstone Disassembly Engine, http://www.capstone-engine.org */")
print("/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */")
print("/* Automatically generated file, do not edit! */\n")
print('#include "../../MCInst.h"')
print('#include "../../LEB128.h"')
print("")

print("""
// Helper function for extracting fields from encoded instructions.

//#if defined(_MSC_VER) && !defined(__clang__)
//__declspec(noinline)
//#endif

#define FieldFromInstruction(fname, InsnType) \\
static InsnType fname(InsnType insn, unsigned startBit, unsigned numBits) \\
{ \\
  InsnType fieldMask; \\
  if (numBits == sizeof(InsnType) * 8) \\
    fieldMask = (InsnType)(-1LL); \\
  else \\
    fieldMask = (((InsnType)1 << numBits) - 1) << startBit; \\
  return (insn & fieldMask) >> startBit; \\
}
""")


# extract text between <>
# printSVERegOp<'q'>
def extract_brackets(line):
    return line[line.index('<')+1 : line.index('>')]

# delete text between <>, including <>
# printSVERegOp<'q'>
def del_brackets(line):
    return line[:line.index('<')] + line[line.index('>') + 1:]


# skip printing some lines?
skip_print = True
# adding slash at the end of the line for C macro?
adding_slash = False
# skip LLVM_DEBUG
llvm_debug = False

def print_line(line):
    if skip_print is True:
        return
    if adding_slash:
        # skip blank line
        if (len(line.strip()) == 0):
            return
        # // must be handled
        if '//' in line:
            line = line.replace('//', '/*')
            line += ' */'
        print(line + ' \\')
    else:
        print(line)


for line in lines:
    line2 = line.rstrip()

    if '#include ' in line2:
        continue

    # skip until the first decoder table
    elif skip_print and 'static const uint8_t DecoderTable' in line2:
        skip_print = False

    elif 'End llvm namespace' in line2:
        # done
        break

    elif 'llvm_unreachable' in line2:
        line2 = line2.replace('llvm_unreachable', '/* llvm_unreachable')
        line2 += '*/ '
        if '"Invalid index!"' in line2:
            pass
            #line2 += '\n  return true;'

    elif 'Bits[' in line2:
        if sys.argv[2] == 'ARM':
            line2 = line2.replace('Bits[', 'ARM_getFeatureBits(MI->csh->mode, ')
            line2 = line2.replace(']', ')')
        elif sys.argv[2] == 'AArch64':
            line2 = line2.replace('Bits[', 'AArch64_getFeatureBits(')
            line2 = line2.replace(']', ')')

    elif 'static bool checkDecoderPredicate(unsigned Idx, const FeatureBitset& Bits) {' in line2:
        line2 = 'static bool checkDecoderPredicate(unsigned Idx, MCInst *MI)\n{'

    elif 'checkDecoderPredicate(PIdx, ' in line2:
        line2 = line2.replace(', Bits)', ', MI)')

    elif 'template<typename InsnType>' in line2:
        continue

    elif 'static DecodeStatus decodeToMCInst' in line2:
        line2 = '#define DecodeToMCInst(fname, fieldname, InsnType) \\\n' + \
                'static DecodeStatus fname(DecodeStatus S, unsigned Idx, InsnType insn, MCInst *MI, \\\n' + \
                '\t\tuint64_t Address, bool *Decoder) \\\n{'
        adding_slash = True

    elif 'fieldFromInstruction' in line2:
        line2 = line2.replace('fieldFromInstruction', 'fieldname')
        if 'InsnType FieldValue' in line2:
            line2 = line2.replace('InsnType ', '')

    elif 'DecodeComplete = true;' in line2:
        # dead code
        continue

    elif 'bool &DecodeComplete) {' in line2:
        continue

    elif line2 == '}':
        if adding_slash:
            adding_slash = False

    elif 'static DecodeStatus decodeInstruction' in line2:
        line2 = '#define DecodeInstruction(fname, fieldname, decoder, InsnType) \\\n' + \
                'static DecodeStatus fname(const uint8_t DecodeTable[], MCInst *MI, \\\n' + \
                '\t\tInsnType insn, uint64_t Address) \\\n{ \\\n' + \
                '  unsigned Start, Len, NumToSkip, PIdx, Opc, DecodeIdx; \\\n' + \
                '  InsnType Val, FieldValue, PositiveMask, NegativeMask; \\\n' + \
                '  bool Pred, Fail, DecodeComplete = true; \\\n' + \
                '  uint32_t ExpectedValue;'

        adding_slash = True
        print_line(line2)
        # skip printing few lines
        skip_print = True
    elif 'const MCSubtargetInfo &STI' in line2:
        skip_print = False
        # skip this line
        continue
    elif 'Bits = STI.getFeatureBits()' in line2:
        # skip this line
        continue
    elif 'errs() << ' in line2:
        continue
    elif 'unsigned Start =' in line2:
        line2 = line2.replace('unsigned ', '')
    elif 'unsigned Len =' in line2:
        line2 = line2.replace('unsigned ', '')
    elif 'unsigned Len;' in line2:
        continue
    elif 'MCInst TmpMI;' in line2:
        continue
    elif 'bool Pred;' in line2:
        continue
    elif 'bool DecodeComplete;' in line2:
        continue
    elif 'unsigned NumToSkip =' in line2:
        line2 = line2.replace('unsigned ', '')
    elif 'unsigned PIdx =' in line2:
        line2 = line2.replace('unsigned ', '')
    elif 'unsigned Opc =' in line2:
        line2 = line2.replace('unsigned ', '')
    elif 'unsigned DecodeIdx =' in line2:
        line2 = line2.replace('unsigned ', '')
    elif 'InsnType Val =' in line2:
        line2 = line2.replace('InsnType ', '')
    elif 'bool Fail' in line2:
        line2 = line2.replace('bool ', '')
    elif 'InsnType PositiveMask =' in line2:
        line2 = line2.replace('InsnType ', '')
    elif 'InsnType NegativeMask =' in line2:
        line2 = line2.replace('InsnType ', '')
    elif 'uint32_t ExpectedValue' in line2:
        line2 = line2.replace('uint32_t ', '')
    elif 'ptrdiff_t Loc = ' in line2:
        continue
    elif 'LLVM_DEBUG(' in line2:
        # just this line?
        if ');' in line2:
            continue
        skip_print = True
        llvm_debug = True
        continue
    elif skip_print and llvm_debug and ');' in line2:
        llvm_debug = False
        skip_print = False
        continue
    elif 'decodeToMCInst(' in line2:
        line2 = line2.replace('decodeToMCInst', 'decoder')
        line2 = line2.replace('DecodeComplete);', '&DecodeComplete);')
        line2 = line2.replace(', DisAsm', '')
        line2 = line2.replace(', TmpMI', ', MI')
    elif 'TmpMI.setOpcode(Opc);' in line2:
        line2 = '      MCInst_setOpcode(MI, Opc);'
    elif 'MI.setOpcode(Opc);' in line2:
        line2 = '      MCInst_setOpcode(MI, Opc);'
    elif 'MI.clear();' in line2:
        line2 = '      MCInst_clear(MI);'
    elif 'assert(' in line2:
        line2 = line2.replace('assert(', '/* assert(')
        line2 += ' */'
    elif 'Check(S, ' in line2:
        line2 = line2.replace('Check(S, ', 'Check(&S, ')
        if 'DecodeImm8OptLsl<' in line2:
            param = extract_brackets(line2)
            line2 = del_brackets(line2)
            line2 = line2.replace(', Decoder)', ', Decoder, %s)' %param)
        elif 'DecodeSImm<' in line2:
            param = extract_brackets(line2)
            line2 = del_brackets(line2)
            line2 = line2.replace(', Decoder)', ', Decoder, %s)' %param)
        if 'DecodeComplete = false; ' in line2:
            line2 = line2.replace('DecodeComplete = false; ', '')
    elif 'decodeUImmOperand<' in line2 or 'decodeSImmOperand<' in line2 :
        # decodeUImmOperand<5>(MI, tmp, Address, Decoder)
        param = extract_brackets(line2)
        line2 = del_brackets(line2)
        line2 = line2.replace(', Decoder)', ', Decoder, %s)' %param)
    elif 'MI.addOperand(MCOperand::createImm(tmp));' in line2:
        line2 = '    MCOperand_CreateImm0(MI, tmp);'
    elif 'MI = TmpMI;' in line2:
        line2 = ''
        #line2 = line2.replace('TmpMI', '&TmpMI')

    line2 = line2.replace('::', '_')
    print_line(line2)

if sys.argv[2] == 'ARM':
    print("""
FieldFromInstruction(fieldFromInstruction_2, uint16_t)
DecodeToMCInst(decodeToMCInst_2, fieldFromInstruction_2, uint16_t)
DecodeInstruction(decodeInstruction_2, fieldFromInstruction_2, decodeToMCInst_2, uint16_t)

FieldFromInstruction(fieldFromInstruction_4, uint32_t)
DecodeToMCInst(decodeToMCInst_4, fieldFromInstruction_4, uint32_t)
DecodeInstruction(decodeInstruction_4, fieldFromInstruction_4, decodeToMCInst_4, uint32_t)
""")

if sys.argv[2] in ('AArch64', 'PPC'):
    print("""
FieldFromInstruction(fieldFromInstruction_4, uint32_t)
DecodeToMCInst(decodeToMCInst_4, fieldFromInstruction_4, uint32_t)
DecodeInstruction(decodeInstruction_4, fieldFromInstruction_4, decodeToMCInst_4, uint32_t)
""")

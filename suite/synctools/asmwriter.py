#!/usr/bin/python
# convert LLVM GenAsmWriter.inc for Capstone disassembler.
# by Nguyen Anh Quynh, 2019

import sys

if len(sys.argv) == 1:
    print("Syntax: %s <GenAsmWriter.inc> <Output-GenAsmWriter.inc> <Output-GenRegisterName.inc> <arch>" %sys.argv[0])
    sys.exit(1)

arch = sys.argv[4] 
f = open(sys.argv[1])
lines = f.readlines()
f.close()

f1 = open(sys.argv[2], 'w+')

f2 = open(sys.argv[3], 'w+')

f1.write("/* Capstone Disassembly Engine, http://www.capstone-engine.org */\n")
f1.write("/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */\n")
f1.write("\n")

f2.write("/* Capstone Disassembly Engine, http://www.capstone-engine.org */\n")
f2.write("/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */\n")
f2.write("\n")

need_endif = False
in_getRegisterName = False
in_printAliasInstr = False
fragment_no = None
skip_printing = False

skip_line = 0
skip_count = 0

def replace_getOp(line):
    line2 = line
    if 'MI->getOperand(0)' in line:
        line2 = line.replace('MI->getOperand(0)', 'MCInst_getOperand(MI, 0)')
    elif 'MI->getOperand(1)' in line:
        line2 = line.replace('MI->getOperand(1)', 'MCInst_getOperand(MI, 1)')
    elif 'MI->getOperand(2)' in line:
        line2 = line.replace('MI->getOperand(2)', 'MCInst_getOperand(MI, 2)')
    elif 'MI->getOperand(3)' in line:
        line2 = line.replace('MI->getOperand(3)', 'MCInst_getOperand(MI, 3)')
    elif 'MI->getOperand(4)' in line:
        line2 = line.replace('MI->getOperand(4)', 'MCInst_getOperand(MI, 4)')
    elif 'MI->getOperand(5)' in line:
        line2 = line.replace('MI->getOperand(5)', 'MCInst_getOperand(MI, 5)')
    elif 'MI->getOperand(6)' in line:
        line2 = line.replace('MI->getOperand(6)', 'MCInst_getOperand(MI, 6)')
    elif 'MI->getOperand(7)' in line:
        line2 = line.replace('MI->getOperand(7)', 'MCInst_getOperand(MI, 7)')
    elif 'MI->getOperand(8)' in line:
        line2 = line.replace('MI->getOperand(8)', 'MCInst_getOperand(MI, 8)')
    return line2

def replace_getReg(line):
    line2 = line
    if 'MI->getOperand(0).getReg()' in line:
        line2 = line.replace('MI->getOperand(0).getReg()', 'MCOperand_getReg(MCInst_getOperand(MI, 0))')
    elif 'MI->getOperand(1).getReg()' in line:
        line2 = line.replace('MI->getOperand(1).getReg()', 'MCOperand_getReg(MCInst_getOperand(MI, 1))')
    elif 'MI->getOperand(2).getReg()' in line:
        line2 = line.replace('MI->getOperand(2).getReg()', 'MCOperand_getReg(MCInst_getOperand(MI, 2))')
    elif 'MI->getOperand(3).getReg()' in line:
        line2 = line.replace('MI->getOperand(3).getReg()', 'MCOperand_getReg(MCInst_getOperand(MI, 3))')
    elif 'MI->getOperand(4).getReg()' in line:
        line2 = line.replace('MI->getOperand(4).getReg()', 'MCOperand_getReg(MCInst_getOperand(MI, 4))')
    elif 'MI->getOperand(5).getReg()' in line:
        line2 = line.replace('MI->getOperand(5).getReg()', 'MCOperand_getReg(MCInst_getOperand(MI, 5))')
    elif 'MI->getOperand(6).getReg()' in line:
        line2 = line.replace('MI->getOperand(6).getReg()', 'MCOperand_getReg(MCInst_getOperand(MI, 6))')
    elif 'MI->getOperand(7).getReg()' in line:
        line2 = line.replace('MI->getOperand(7).getReg()', 'MCOperand_getReg(MCInst_getOperand(MI, 7))')
    elif 'MI->getOperand(8).getReg()' in line:
        line2 = line.replace('MI->getOperand(8).getReg()', 'MCOperand_getReg(MCInst_getOperand(MI, 8))')
    return line2

# extract param between text()
# MRI.getRegClass(AArch64::GPR32spRegClassID).contains(MI->getOperand(1).getReg()))
def extract_paren(line, text):
    i = line.index(text)
    return line[line.index('(', i)+1 : line.index(')', i)]


# extract text between <>
# printSVERegOp<'q'>
def extract_brackets(line):
    if '<' in line:
        return line[line.index('<')+1 : line.index('>')]
    else:
        return ''

# delete text between <>, including <>
# printSVERegOp<'q'>
def del_brackets(line):
    if '<' in line:
        return line[:line.index('<')] + line[line.index('>') + 1:]
    else:
        return line


def print_line(line):
    line = line.replace('::', '_')
    line = line.replace('nullptr', 'NULL')
    if not skip_printing:
        if in_getRegisterName:
            f2.write(line + "\n")
        else:
            f1.write(line + "\n")


for line in lines:
    line = line.rstrip()
    #print("@", line)

    # skip Alias
    if arch.upper() == 'X86':
        if 'PRINT_ALIAS_INSTR' in line:
            # done
            break

    if skip_line:
        skip_count += 1
        if skip_count <= skip_line:
            # skip this line
            continue
        else:
            # skip enough number of lines, reset counters
            skip_line = 0
            skip_count = 0

    if "::printInstruction" in line:
        if arch.upper() in ('AARCH64', 'ARM64'):
            #print_line("static void printInstruction(MCInst *MI, SStream *O, MCRegisterInfo *MRI)\n{")
            print_line("static void printInstruction(MCInst *MI, SStream *O)\n{")
        else:
            print_line("static void printInstruction(MCInst *MI, SStream *O)\n{")
    elif 'LLVM_NO_PROFILE_INSTRUMENT_FUNCTION' in line:
        continue
    elif 'AArch64InstPrinter::getMnemonic' in line:
        print_line("static uint64_t getMnemonic(MCInst *MI, SStream *O, unsigned int opcode) {")
    elif 'return {AsmStrs+(Bits' in line:
        tmp = line.split(',')
        prntStr = tmp[0].split('{')[1]
        print_line("\tSStream_concat0(O, " + prntStr + ");")
        print_line("\treturn Bits;")
    elif 'MnemonicInfo = getMnemonic(' in line:
        continue
    elif 'O << MnemonicInfo' in line:
        continue
    elif 'uint64_t Bits = MnemonicInfo' in line:
        print_line("\tuint64_t Bits = getMnemonic(MI, O, opcode);")
    elif 'const char *AArch64InstPrinter::' in line:
        continue
    elif 'getRegisterName(' in line:
        if 'unsigned AltIdx' in line:
            print_line("static const char *getRegisterName(unsigned RegNo, unsigned AltIdx)\n{")
        else:
            print_line("static const char *getRegisterName(unsigned RegNo)\n{")
    elif 'getRegisterName' in line:
        in_getRegisterName = True
        print_line(line)
    elif '::printAliasInstr' in line:
        if arch.upper() in ('AARCH64', 'PPC'):
            print_line("static char *printAliasInstr(MCInst *MI, SStream *OS, MCRegisterInfo *MRI)\n{")
            print_line('  #define GETREGCLASS_CONTAIN(_class, _reg) MCRegisterClass_contains(MCRegisterInfo_getRegClass(MRI, _class), MCOperand_getReg(MCInst_getOperand(MI, _reg)))')
        else:
            print_line("static bool printAliasInstr(MCInst *MI, SStream *OS)\n{")
        print_line("  unsigned int I = 0, OpIdx, PrintMethodIdx;")
        print_line("  char *tmpString;")
        in_printAliasInstr = True
    elif 'STI.getFeatureBits()[' in line:
        if arch.upper() == 'ARM':
            line2 = line.replace('STI.getFeatureBits()[', 'ARM_getFeatureBits(MI->csh->mode, ')
        elif arch.upper() == 'AARCH64':
            line2 = line.replace('STI.getFeatureBits()[', 'AArch64_getFeatureBits(')
        line2 = line2.replace(']', ')')
        print_line(line2)
    elif 'lookupBTIByEncoding' in line:
        line = line.replace('AArch64BTIHint::', '')
        line = line.replace('MCOp.getImm()', 'MCOperand_getImm(MCOp)')
        print_line(line)
    elif 'lookupPSBByEncoding' in line:
        line = line.replace('AArch64PSBHint::', '')
        line = line.replace('MCOp.getImm()', 'MCOperand_getImm(MCOp)')
        print_line(line)
    elif ', STI, ' in line:
        line2 = line.replace(', STI, ', ', ')

        if 'printSVELogicalImm<' in line:
            if 'int16' in line:
                line2 = line2.replace('printSVELogicalImm', 'printSVELogicalImm16')
                line2 = line2.replace('<int16_t>', '')
            elif 'int32' in line: 
                line2 = line2.replace('printSVELogicalImm', 'printSVELogicalImm32')
                line2 = line2.replace('<int32_t>', '')
            else:
                line2 = line2.replace('printSVELogicalImm', 'printSVELogicalImm64')
                line2 = line2.replace('<int64_t>', '')

        if 'MI->getOperand(' in line:
            line2 = replace_getOp(line2)

        # C++ template
        if 'printPrefetchOp' in line2:
            param = extract_brackets(line2)
            if param == '':
                param = 'false'
            line2 = del_brackets(line2)
            line2 = line2.replace(', O);', ', O, %s);' %param)
            line2 = line2.replace(', OS);', ', OS, %s);' %param)
        elif '<false>' in line2:
            line2 = line2.replace('<false>', '')
            line2 = line2.replace(', O);', ', O, false);')
            line2 = line2.replace('STI, ', '')
        elif '<true>' in line:
            line2 = line2.replace('<true>', '')
            line2 = line2.replace(', O);', ', O, true);')
            line2 = line2.replace('STI, ', '')
        elif 'printAdrLabelOperand' in line:
            # C++ template
            if '<0>' in line:
                line2 = line2.replace('<0>', '')
                line2 = line2.replace(', O);', ', O, 0);')
            elif '<1>' in line:
                line2 = line2.replace('<1>', '')
                line2 = line2.replace(', O);', ', O, 1);')
            elif '<2>' in line:
                line2 = line2.replace('<2>', '')
                line2 = line2.replace(', O);', ', O, 2);')
        elif 'printImm8OptLsl' in line2:
            param = extract_brackets(line2)
            line2 = del_brackets(line2)
            if '8' in param or '16' in param or '32' in param:
                line2 = line2.replace('printImm8OptLsl', 'printImm8OptLsl32')
            elif '64' in param:
                line2 = line2.replace('printImm8OptLsl', 'printImm8OptLsl64')
        elif 'printLogicalImm' in line2:
            param = extract_brackets(line2)
            line2 = del_brackets(line2)
            if '8' in param or '16' in param or '32' in param:
                line2 = line2.replace('printLogicalImm', 'printLogicalImm32')
            elif '64' in param:
                line2 = line2.replace('printLogicalImm', 'printLogicalImm64')
        elif 'printSVERegOp' in line2 or 'printGPRSeqPairsClassOperand' in line2 or 'printTypedVectorList' in line2 or 'printPostIncOperand' in line2 or 'printImmScale' in line2 or 'printRegWithShiftExtend' in line2 or 'printUImm12Offset' in line2 or 'printExactFPImm' in line2 or 'printMemExtend' in line2 or 'printZPRasFPR' in line2 or 'printMatrixTileVector' in line2 or 'printMatrix<' in line2 or 'printSImm' in line2:
            param = extract_brackets(line2)
            if param == '':
                param = '0'
            line2 = del_brackets(line2)
            line2 = line2.replace(', O);', ', O, %s);' %param)
            line2 = line2.replace(', OS);', ', OS, %s);' %param)
        elif 'printComplexRotationOp' in line:
            # printComplexRotationOp<90, 0>(MI, 5, STI, O);
            bracket_content = line2[line2.index('<') + 1 : line2.index('>')]
            line2 = line2.replace('<' + bracket_content + '>', '')
            line2 = line2.replace(' O);', ' O, %s);' %bracket_content)
        elif 'printAlignedLabel' in line2 or 'printAdrpLabel' in line2:
            line2 = line2.replace('Address, ', '')

        print_line(line2)
    elif "static const char AsmStrs[]" in line:
        print_line("#ifndef CAPSTONE_DIET")
        print_line("  static const char AsmStrs[] = {")
        need_endif = True
    elif "static const char AsmStrsNoRegAltName[]" in line:
        print_line("#ifndef CAPSTONE_DIET")
        print_line("  static const char AsmStrsNoRegAltName[] = {")
        need_endif = True
    elif line == '  O << "\\t";':
        print_line("  unsigned int opcode = MCInst_getOpcode(MI);")
        print_line('  // printf("opcode = %u\\n", opcode);');
    elif 'MI->getOpcode()' in line:
        if 'switch' in line:
            line2 = line.replace('MI->getOpcode()', 'MCInst_getOpcode(MI)')
        else:
            line2 = line.replace('MI->getOpcode()', 'opcode')
        print_line(line2)

    elif 'O << ' in line:
        if '"' in line:
            line2 = line.lower()
            line2 = line2.replace('o << ', 'SStream_concat0(O, ');
        else:
            line2 = line.replace('O << ', 'SStream_concat0(O, ');
        line2 = line2.replace("'", '"')
        line2 = line2.replace(';', ');')
        if '" : "' in line2:    # "segment : offset" in X86
            line2 = line2.replace('" : "', '":"')

        # ARM
        print_line(line2)

        if '", #0"' in line2:
            print_line('    op_addImm(MI, 0);')

        if '", #1"' in line2:
            print_line('    op_addImm(MI, 1);')

        # PowerPC
        if '", 268"' in line2:
            print_line('    op_addImm(MI, 268);')

        elif '", 256"' in line2:
            print_line('    op_addImm(MI, 256);')

        elif '", 0, "' in line2 or '", 0"' in line2:
            print_line('    op_addImm(MI, 0);')

        elif '", -1"' in line2:
            print_line('    op_addImm(MI, -1);')
        

        if '], [' in line2 or ']!, [' in line2:
            print_line('    set_mem_access(MI, false);')
            print_line('    set_mem_access(MI, true);')
        
        elif "\"[\"" in line2:
            # Check for SME_Index specific string of only "["
            print_line('    set_sme_index(MI, true);')

        elif '[' in line2:
            if not '[]' in line2:
                print_line('    set_mem_access(MI, true);')

        elif ']' in line2:
            if not '[]' in line2:
                print_line('    set_mem_access(MI, false);')

        if '".f64\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F64);')
        elif '".f32\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F32);')
        elif '".f16\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F16);')
        elif '".s64\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_S64);')
        elif '".s32\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_S32);')
        elif '".s16\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_S16);')
        elif '".s8\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_S8);')
        elif '".u64\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_U64);')
        elif '".u32\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_U32);')
        elif '".u16\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_U16);')
        elif '".u8\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_U8);')
        elif '".i64\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_I64);')
        elif '".i32\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_I32);')
        elif '".i16\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_I16);')
        elif '".i8\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_I8);')
        elif '".f16.f64\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F16F64);')
        elif '".f64.f16\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F64F16);')
        elif '".f16.f32\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F16F32);')
        elif '".f32.f16\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F32F16);')
        elif '".f64.f32\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F64F32);')
        elif '".f32.f64\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F32F64);')
        elif '".s32.f32\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_S32F32);')
        elif '".f32.s32\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F32S32);')
        elif '".u32.f32\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_U32F32);')
        elif '".f32.u32\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F32U32);')
        elif '".p8\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_P8);')
        elif '".f64.s16\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F64S16);')
        elif '".s16.f64\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_S16F64);')
        elif '".f32.s16\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F32S16);')
        elif '".s16.f32\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_S16F32);')
        elif '".f64.s32\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F64S32);')
        elif '".s32.f64\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_S32F64);')
        elif '".f64.u16\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F64U16);')
        elif '".u16.f64\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_U16F64);')
        elif '".f32.u16\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F32U16);')
        elif '".u16.f32\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_U16F32);')
        elif '".f64.u32\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F64U32);')
        elif '".u32.f64\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_U32F64);')
        elif '".f16.u32\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F16U32);')
        elif '".u32.f16\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_U32F16);')
        elif '".f16.u16\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_F16U16);')
        elif '".u16.f16\\t"' in line2:
            print_line('    ARM_addVectorDataType(MI, ARM_VECTORDATA_U16F16);')
        elif '"\\tlr"' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_LR);')
        elif '"\\tapsr_nzcv, fpscr"' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_APSR_NZCV);')
            print_line('    ARM_addReg(MI, ARM_REG_FPSCR);')
        elif '"\\tpc, lr"' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_PC);')
            print_line('    ARM_addReg(MI, ARM_REG_LR);')
        elif '"\\tfpscr, "' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_FPSCR);')
        elif '"\\tfpexc, "' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_FPEXC);')
        elif '"\\tfpinst, "' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_FPINST);')
        elif '"\\tfpinst2, "' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_FPINST2);')
        elif '"\\tfpsid, "' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_FPSID);')
        elif '"\\tsp, "' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_SP);')
        elif '"\\tsp!, "' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_SP);')
        elif '", apsr"' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_APSR);')
        elif '", spsr"' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_SPSR);')
        elif '", fpscr"' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_FPSCR);')
        elif '", fpscr"' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_FPSCR);')
        elif '", fpexc"' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_FPEXC);')
        elif '", fpinst"' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_FPINST);')
        elif '", fpinst2"' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_FPINST2);')
        elif '", fpsid"' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_FPSID);')
        elif '", mvfr0"' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_MVFR0);')
        elif '", mvfr1"' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_MVFR1);')
        elif '", mvfr2"' in line2:
            print_line('    ARM_addReg(MI, ARM_REG_MVFR2);')
        elif '.8\\t' in line2:
            print_line('    ARM_addVectorDataSize(MI, 8);')
        elif '.16\\t' in line2:
            print_line('    ARM_addVectorDataSize(MI, 16);')
        elif '.32\\t' in line2:
            print_line('    ARM_addVectorDataSize(MI, 32);')
        elif '.64\\t' in line2:
            print_line('    ARM_addVectorDataSize(MI, 64);')
        elif '" ^"' in line2:
            print_line('    ARM_addUserMode(MI);')

        if '.16b' in line2:
            print_line('    arm64_op_addVectorArrSpecifier(MI, ARM64_VAS_16B);')
        elif '.8b' in line2:
            print_line('    arm64_op_addVectorArrSpecifier(MI, ARM64_VAS_8B);')
        elif '.4b' in line2:
            print_line('    arm64_op_addVectorArrSpecifier(MI, ARM64_VAS_4B);')
        elif '.b' in line2:
            print_line('    arm64_op_addVectorArrSpecifier(MI, ARM64_VAS_1B);')
        elif '.8h' in line2:
            print_line('    arm64_op_addVectorArrSpecifier(MI, ARM64_VAS_8H);')
        elif '.4h' in line2:
            print_line('    arm64_op_addVectorArrSpecifier(MI, ARM64_VAS_4H);')
        elif '.2h' in line2:
            print_line('    arm64_op_addVectorArrSpecifier(MI, ARM64_VAS_2H);')
        elif '.h' in line2:
            print_line('    arm64_op_addVectorArrSpecifier(MI, ARM64_VAS_1H);')
        elif '.4s' in line2:
            print_line('    arm64_op_addVectorArrSpecifier(MI, ARM64_VAS_4S);')
        elif '.2s' in line2:
            print_line('    arm64_op_addVectorArrSpecifier(MI, ARM64_VAS_2S);')
        elif '.s' in line2:
            print_line('    arm64_op_addVectorArrSpecifier(MI, ARM64_VAS_1S);')
        elif '.2d' in line2:
            print_line('    arm64_op_addVectorArrSpecifier(MI, ARM64_VAS_2D);')
        elif '.1d' in line2:
            print_line('    arm64_op_addVectorArrSpecifier(MI, ARM64_VAS_1D);')
        elif '.1q' in line2:
            print_line('    arm64_op_addVectorArrSpecifier(MI, ARM64_VAS_1Q);')

        if '#0.0' in line2:
            print_line('    arm64_op_addFP(MI, 0);')
        elif '#0' in line2:
            print_line('    arm64_op_addImm(MI, 0);')
        elif '#8' in line2:
            print_line('    arm64_op_addImm(MI, 8);')
        elif '#16' in line2:
            print_line('    arm64_op_addImm(MI, 16);')
        elif '#32' in line2:
            print_line('    arm64_op_addImm(MI, 32);')

        # X86
        if '", %rax"' in line2 or '", rax"' in line2:
            print_line('    op_addReg(MI, X86_REG_RAX);')
        elif '", %eax"' in line2 or '", eax"' in line2:
            print_line('    op_addReg(MI, X86_REG_EAX);')
        elif '", %ax"' in line2 or '", ax"' in line2:
            print_line('    op_addReg(MI, X86_REG_AX);')
        elif '", %al"' in line2 or '", al"' in line2:
            print_line('    op_addReg(MI, X86_REG_AL);')
        elif '", %dx"' in line2 or '", dx"' in line2:
            print_line('    op_addReg(MI, X86_REG_DX);')
        elif '", %st(0)"' in line2 or '", st(0)"' in line2:
            print_line('    op_addReg(MI, X86_REG_ST0);')
        elif '", 1"' in line2:
            print_line('    op_addImm(MI, 1);')
        elif '", cl"' in line2:
            print_line('    op_addReg(MI, X86_REG_CL);')
        elif '"{1to2}, "' in line2:
            print_line('    op_addAvxBroadcast(MI, X86_AVX_BCAST_2);')
        elif '"{1to4}, "' in line2:
            print_line('    op_addAvxBroadcast(MI, X86_AVX_BCAST_4);')
        elif '"{1to8}, "' in line2:
            print_line('    op_addAvxBroadcast(MI, X86_AVX_BCAST_8);')
        elif '"{1to16}, "' in line2:
            print_line('    op_addAvxBroadcast(MI, X86_AVX_BCAST_16);')
        elif '{z}{sae}' in line2:
            print_line('    op_addAvxSae(MI);')
            print_line('    op_addAvxZeroOpmask(MI);')
        elif ('{z}' in line2):
            print_line('    op_addAvxZeroOpmask(MI);')
        elif '{sae}' in line2:
            print_line('    op_addAvxSae(MI);')
    elif 'llvm_unreachable("Invalid command number.");' in line:
        line2 = line.replace('llvm_unreachable("Invalid command number.");', '// unreachable')
        print_line(line2)
    elif ('assert(' in line) or ('assert (' in line):
        pass
    elif 'Invalid alt name index' in line:
        pass
    elif '::' in line and 'case ' in line:
        #print_line(line2)
        print_line(line)
    elif 'MI->getNumOperands()' in line:
        line2 = line.replace('MI->getNumOperands()', 'MCInst_getNumOperands(MI)')
        print_line(line2)
    elif 'const MCOperand &MCOp' in line:
        line2 = line.replace('const MCOperand &MCOp', 'MCOperand *MCOp')
        print_line(line2)
    elif 'MI->getOperand(0).isImm()' in line:
        line2 = line.replace('MI->getOperand(0).isImm()', 'MCOperand_isImm(MCInst_getOperand(MI, 0))')
        print_line(line2)
    elif 'MI->getOperand(1).isImm()' in line:
        line2 = line.replace('MI->getOperand(1).isImm()', 'MCOperand_isImm(MCInst_getOperand(MI, 1))')
        print_line(line2)
    elif 'MI->getOperand(2).isImm()' in line:
        line2 = line.replace('MI->getOperand(2).isImm()', 'MCOperand_isImm(MCInst_getOperand(MI, 2))')
        print_line(line2)
    elif 'MI->getOperand(3).isImm()' in line:
        line2 = line.replace('MI->getOperand(3).isImm()', 'MCOperand_isImm(MCInst_getOperand(MI, 3))')
        print_line(line2)
    elif 'MI->getOperand(4).isImm()' in line:
        line2 = line.replace('MI->getOperand(4).isImm()', 'MCOperand_isImm(MCInst_getOperand(MI, 4))')
        print_line(line2)
    elif 'MI->getOperand(5).isImm()' in line:
        line2 = line.replace('MI->getOperand(5).isImm()', 'MCOperand_isImm(MCInst_getOperand(MI, 5))')
        print_line(line2)
    elif 'MI->getOperand(6).isImm()' in line:
        line2 = line.replace('MI->getOperand(6).isImm()', 'MCOperand_isImm(MCInst_getOperand(MI, 6))')
        print_line(line2)
    elif 'MI->getOperand(7).isImm()' in line:
        line2 = line.replace('MI->getOperand(7).isImm()', 'MCOperand_isImm(MCInst_getOperand(MI, 7))')
        print_line(line2)
    elif 'MI->getOperand(8).isImm()' in line:
        line2 = line.replace('MI->getOperand(8).isImm()', 'MCOperand_isImm(MCInst_getOperand(MI, 8))')
        print_line(line2)
    elif 'MI->getOperand(0).getImm()' in line:
        line2 = line.replace('MI->getOperand(0).getImm()', 'MCOperand_getImm(MCInst_getOperand(MI, 0))')
        print_line(line2)
    elif 'MI->getOperand(1).getImm()' in line:
        line2 = line.replace('MI->getOperand(1).getImm()', 'MCOperand_getImm(MCInst_getOperand(MI, 1))')
        print_line(line2)
    elif 'MI->getOperand(2).getImm()' in line:
        line2 = line.replace('MI->getOperand(2).getImm()', 'MCOperand_getImm(MCInst_getOperand(MI, 2))')
        print_line(line2)
    elif 'MI->getOperand(3).getImm()' in line:
        line2 = line.replace('MI->getOperand(3).getImm()', 'MCOperand_getImm(MCInst_getOperand(MI, 3))')
        print_line(line2)
    elif 'MI->getOperand(4).getImm()' in line:
        line2 = line.replace('MI->getOperand(4).getImm()', 'MCOperand_getImm(MCInst_getOperand(MI, 4))')
        print_line(line2)
    elif 'MI->getOperand(5).getImm()' in line:
        line2 = line.replace('MI->getOperand(5).getImm()', 'MCOperand_getImm(MCInst_getOperand(MI, 5))')
        print_line(line2)
    elif 'MI->getOperand(6).getImm()' in line:
        line2 = line.replace('MI->getOperand(6).getImm()', 'MCOperand_getImm(MCInst_getOperand(MI, 6))')
        print_line(line2)
    elif 'MI->getOperand(7).getImm()' in line:
        line2 = line.replace('MI->getOperand(7).getImm()', 'MCOperand_getImm(MCInst_getOperand(MI, 7))')
        print_line(line2)
    elif 'MI->getOperand(8).getImm()' in line:
        line2 = line.replace('MI->getOperand(8).getImm()', 'MCOperand_getImm(MCInst_getOperand(MI, 8))')
        print_line(line2)
    elif 'MRI.getRegClass(' in line:
        classid = extract_paren(line, 'getRegClass(')
        operand = extract_paren(line, 'getOperand')
        line2 = line.replace('MI->getNumOperands()', 'MCInst_getNumOperands(MI)')
        line2 = '        GETREGCLASS_CONTAIN(%s, %s)' %(classid, operand)
        if line.endswith('())) {'):
            line2 += ') {'
        elif line.endswith(' {'):
            line2 += ' {'
        elif line.endswith(' &&'):
            line2 += ' &&'
        print_line(line2)
    elif 'MI->getOperand(' in line and 'isReg' in line:
        operand = extract_paren(line, 'getOperand')
        line2 = '        MCOperand_isReg(MCInst_getOperand(MI, %s))' %(operand)
        # MI->getOperand(1).isReg() &&
        if line.endswith(' {'):
            line2 += ' {'
        elif line.endswith(' &&'):
            line2 += ' &&'
        print_line(line2)
    elif 'MI->getOperand(' in line and 'getReg' in line:
        line2 = replace_getReg(line)
        # one more time
        line2 = replace_getReg(line2)
        print_line(line2)
    elif '    return false;' in line and in_printAliasInstr:
        print_line('    return NULL;')
    elif 'MCOp.isImm()' in line:
        line2 = line.replace('MCOp.isImm()', 'MCOperand_isImm(MCOp)')
        print_line(line2)
    elif 'MCOp.getImm()' in line:
        line2 = line.replace('MCOp.getImm()', 'MCOperand_getImm(MCOp)')
        if 'int64_t Val =' in line:
            line2 = line2.replace('int64_t Val =', 'Val =')
        print_line(line2)
    elif 'isSVEMaskOfIdenticalElements<' in line:
        if 'int8' in line:
            line2 = line.replace('isSVEMaskOfIdenticalElements', 'isSVEMaskOfIdenticalElements8')
            line2 = line2.replace('<int8_t>', '')
        elif 'int16' in line:
            line2 = line.replace('isSVEMaskOfIdenticalElements', 'isSVEMaskOfIdenticalElements16')
            line2 = line2.replace('<int16_t>', '')
        elif 'int32' in line: 
            line2 = line.replace('isSVEMaskOfIdenticalElements', 'isSVEMaskOfIdenticalElements32')
            line2 = line2.replace('<int32_t>', '')
        else:
            line2 = line.replace('isSVEMaskOfIdenticalElements', 'isSVEMaskOfIdenticalElements64')
            line2 = line2.replace('<int64_t>', '')
        print_line(line2)
    elif 'switch (PredicateIndex) {' in line:
        print_line('  int64_t Val;')
        print_line(line)
    elif 'uint32_t(' in line and in_printAliasInstr:
        line = line.replace('uint32_t(', '')
        line = line.replace(')', '')
        print_line(line)
    elif '#ifndef NDEBUG' in line and in_printAliasInstr:
        print_line("""
  char *AsmString;
  const size_t OpToSize = sizeof(OpToPatterns) / sizeof(PatternsForOpcode);

  const unsigned opcode = MCInst_getOpcode(MI);

  // Check for alias
  int OpToIndex = 0;
  for(int i = 0; i < OpToSize; i++){
    if(OpToPatterns[i].Opcode == opcode){
      OpToIndex = i;
      break;
    }
  }
  // Chech for match
  if(opcode != OpToPatterns[OpToIndex].Opcode)
    return NULL;

  const PatternsForOpcode opToPat = OpToPatterns[OpToIndex];

  // Try all patterns for this opcode
  uint32_t AsmStrOffset = ~0U;
  int patIdx = opToPat.PatternStart;
  while(patIdx < (opToPat.PatternStart + opToPat.NumPatterns)){
    // Check operand count first
    if(MCInst_getNumOperands(MI) != Patterns[patIdx].NumOperands)
      return NULL;
    
    // Test all conditions for this pattern
    int condIdx = Patterns[patIdx].AliasCondStart;
    int opIdx = 0;
    bool allPass = true;
    while(condIdx < (Patterns[patIdx].AliasCondStart + Patterns[patIdx].NumConds)){
      MCOperand *opnd = MCInst_getOperand(MI, opIdx);
      opIdx++;
      // Not concerned with any Feature related conditions as STI is disregarded
      switch (Conds[condIdx].Kind)
      {
      case AliasPatternCond_K_Ignore :
        // Operand can be anything.
        break;
      case AliasPatternCond_K_Reg :
        // Operand must be a specific register.
        allPass = allPass && (MCOperand_isReg(opnd) && MCOperand_getReg(opnd) == Conds[condIdx].Value);
        break;
      case AliasPatternCond_K_TiedReg :
        // Operand must match the register of another operand.
        allPass = allPass && (MCOperand_isReg(opnd) && MCOperand_getReg(opnd) == 
                  MCOperand_getReg(MCInst_getOperand(MI, Conds[condIdx].Value)));
        break;
      case AliasPatternCond_K_Imm :
        // Operand must be a specific immediate.
        allPass = allPass && (MCOperand_isImm(opnd) && MCOperand_getImm(opnd) == Conds[condIdx].Value);
        break;
      case AliasPatternCond_K_RegClass :
        // Operand must be a register in this class. Value is a register class id.
        allPass = allPass && (MCOperand_isReg(opnd) && GETREGCLASS_CONTAIN(Conds[condIdx].Value, (opIdx-1)));
        break;
      case AliasPatternCond_K_Custom :
        // Operand must match some custom criteria.
        allPass = allPass && AArch64InstPrinterValidateMCOperand(opnd, Conds[condIdx].Value);
        break;
      case AliasPatternCond_K_Feature :
      case AliasPatternCond_K_NegFeature :
      case AliasPatternCond_K_OrFeature :
      case AliasPatternCond_K_OrNegFeature :
      case AliasPatternCond_K_EndOrFeatures :
      default :
        break;
      }
      condIdx++;
    }
    if(allPass){
      AsmStrOffset = Patterns[patIdx].AsmStrOffset;
      break;
    }
    patIdx++;
  }

  // If no alias matched, don't print an alias.
  if (AsmStrOffset == ~0U)
    return NULL;

  AsmString = cs_strdup(&AsmStrings[AsmStrOffset]);

  tmpString = cs_strdup(AsmString);

  while (AsmString[I] != ' ' && AsmString[I] != '\\t' &&
        AsmString[I] != '$' && AsmString[I] != '\\0')
    ++I;

  tmpString[I] = 0;
  SStream_concat0(OS, tmpString);

  if (AsmString[I] != '\\0') {
    if (AsmString[I] == ' ' || AsmString[I] == '\\t') {
      SStream_concat0(OS, " ");
      ++I;
    }

    bool isSME = false;
    do {
      if (AsmString[I] == '$') {
        ++I;
        if (AsmString[I] == (char)0xff) {
          ++I;
          OpIdx = AsmString[I++] - 1;
          PrintMethodIdx = AsmString[I++] - 1;
          printCustomAliasOperand(MI, 0, OpIdx, PrintMethodIdx, OS);
        } else
          printOperand(MI, (unsigned)(AsmString[I++]) - 1, OS);
      } else {
        if (AsmString[I] == '[') {
          if (AsmString[I-1] != ' ') {
            set_sme_index(MI, true);
            isSME = true;
          } else {
            set_mem_access(MI, true);
          }
        } else if (AsmString[I] == ']') {
          if (isSME) {
            set_sme_index(MI, false);
            isSME = false;
          } else {
            set_mem_access(MI, false);
          }
        }
        SStream_concat1(OS, AsmString[I++]);
      }
    } while (AsmString[I] != '\\0');
  }
  cs_mem_free(AsmString);
  return tmpString;
}
        """)
        in_printAliasInstr = False
        # skip next few lines
        skip_printing = True
    elif '::printCustomAliasOperand' in line:
        # print again
        skip_printing = False
        print_line('static void printCustomAliasOperand(')
    elif 'const MCSubtargetInfo &STI' in line:
        pass
    elif 'const MCInst *MI' in line:
        line2 = line.replace('const MCInst *MI', 'MCInst *MI')
        print_line(line2)
    elif 'llvm_unreachable("' in line:
        if 'default: ' in line:
            print_line('  default:')
        elif 'llvm_unreachable("Unknown MCOperandPredicate kind")' in line:
            print_line('    return false; // never reach')
        else:
            pass
    elif 'raw_ostream &' in line:
        line2 = line.replace('raw_ostream &', 'SStream *')
        if line2.endswith(' {'):
            line2 = line2.replace(' {', '\n{')
        print_line(line2)
    elif 'printPredicateOperand(' in line and 'STI, ' in line:
        line2 = line.replace('STI, ', '')
        print_line(line2)
    elif '// Fragment ' in line:
        # // Fragment 0 encoded into 6 bits for 51 unique commands.
        tmp = line.strip().split(' ')
        fragment_no = tmp[2]
        print_line(line)
    elif ('switch ((' in line or 'if ((' in line) and 'Bits' in line:
        # switch ((Bits >> 14) & 63) {
        bits = line.strip()
        bits = bits.replace('switch ', '')
        bits = bits.replace('if ', '')
        bits = bits.replace('{', '')
        bits = bits.strip()
        print_line('  // printf("Fragment %s: %%"PRIu64"\\n", %s);' %(fragment_no, bits))
        print_line(line)
    elif not skip_printing:
        print_line(line)

    if line == '  };':
        if need_endif and not in_getRegisterName:
            # endif only for AsmStrs when we are not inside getRegisterName()
            print_line("#endif")
            need_endif = False
    elif 'return AsmStrs+RegAsmOffset[RegNo-1];' in line:
        if in_getRegisterName:
            # return NULL for register name on Diet mode
            print_line("#else")
            print_line("  return NULL;")
            print_line("#endif")
            print_line("}")
            need_endif = False
            in_getRegisterName = False
            # skip 1 line
            skip_line = 1
    elif line == '  }':
        # ARM64
        if in_getRegisterName:
            # return NULL for register name on Diet mode
            print_line("#else")
            print_line("  return NULL;")
            print_line("#endif")
            print_line("}")
            need_endif = False
            in_getRegisterName = False
            # skip 1 line
            skip_line = 1
    elif 'default:' in line:
        # ARM64
        if in_getRegisterName:
            # get the size of RegAsmOffsetvreg[]
            print_line("    return (const char *)(sizeof(RegAsmOffsetvreg)/sizeof(RegAsmOffsetvreg[0]));")


f1.close()
f2.close()

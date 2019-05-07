#!/usr/bin/python
# print MappingInsn.inc file from LLVM GenAsmMatcher.inc, for Capstone disassembler.
# by Nguyen Anh Quynh, 2019

import sys

if len(sys.argv) == 1:
    print("Syntax: %s <GenAsmMatcher.inc> <GenInstrInfo.inc> MappingInsn.inc" %sys.argv[0])
    sys.exit(1)

f = open(sys.argv[3])
mapping = f.readlines()
f.close()

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
# return arch, insn_id_list, insn_lines
def extract_matcher(filename):
    f = open(filename)
    lines = f.readlines()
    f.close()

    match_count = 0
    count = 0
    #insn_lines = []
    insn_id_list = {}
    arch = None
    first_insn = None

    # 1st enum is register enum
    for line in lines:
        line = line.rstrip()
    
        if len(line.strip()) == 0:
            continue
    
        if 'MatchEntry MatchTable1[] = {' in line.strip():
            match_count += 1
            #print(line.strip())
            continue
    
        line = line.strip()
        if match_count == 1:
            count += 1
            if line == '};':
                # done with first enum
                break
            else:
                _arch, mnem, insn_id = extract_insn(line)
                if count == 1:
                    arch, first_insn = _arch, insn_id

                if not insn_id in insn_id_list:
                    # print("***", arch, mnem, insn_id)
                    insn_id_list[insn_id] = mnem
                    #insn_lines.append(line)

    #return arch, first_insn, insn_id_list, insn_lines
    return arch, first_insn, insn_id_list


#arch, first_insn, insn_id_list, match_lines = extract_matcher(sys.argv[1])
arch, first_insn, insn_id_list = extract_matcher(sys.argv[1])
arch = arch.upper()

#for line in insn_id_list:
#    print(line)


#{
#        X86_AAA, X86_INS_AAA,
##ifndef CAPSTONE_DIET
#        { 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
##endif
#},
def print_entry(arch, insn_id, mnem, mapping, mnem_can_be_wrong):
    insn = "%s_%s" %(arch.upper(), insn_id)
    if '64' in insn_id:
        is64bit = '1'
    else:
        is64bit = '0'
    # first, try to find this entry in old MappingInsn.inc file
    for i in range(len(mapping)):
        tmp = mapping[i].split(',')
        if tmp[0].strip() == insn:
            if not mnem_can_be_wrong:
                print('''
{
\t%s_%s, %s_INS_%s, %s,
#ifndef CAPSTONE_DIET
\t%s
#endif
},'''% (arch, insn_id, arch, mnem, is64bit, mapping[i + 2].strip()))
            else:
                if not tmp[1].endswith(mnem):
                    #print("======== cannot find %s, mapping to %s (instead of %s)" %(insn, tmp[1].strip(), mnem))
                    pass
                print('''
{
\t%s_%s, %s, %s,
#ifndef CAPSTONE_DIET
\t%s
#endif
},'''% (arch, insn_id, tmp[1].strip(), is64bit, mapping[i + 2].strip()))

            return

    if mnem_can_be_wrong:
        #print("======== CANNOT FIND %s, mapping to %s" %(insn, mnem))
        pass

    print('''
{
\t%s_%s, %s_INS_%s, %s,
#ifndef CAPSTONE_DIET
\t{ 0 }, { 0 }, { 0 }, 0, 0
#endif
},'''% (arch, insn_id, arch, mnem, is64bit))


# extract from GenInstrInfo.inc, because the insn id is in order
enum_count = 0
meet_insn = False

f = open(sys.argv[2])
lines = f.readlines()
f.close()


count = 0
last_mnem = None

# 1st enum is register enum
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'enum {':
        enum_count += 1
        #print(line.strip())
        continue

    line = line.strip()
    if enum_count == 1:
        if 'INSTRUCTION_LIST_END' in line:
            break
        else:
            insn = None
            if meet_insn:
                # enum items
                insn = line.split('=')[0].strip()
                if 'CALLSTACK' in insn or 'TAILJUMP' in insn:
                    # pseudo instruction
                    insn = None
            elif line.startswith(first_insn):
                insn = line.split('=')[0].strip()
                meet_insn = True

            if insn:
                count += 1
                if insn == 'BSWAP16r_BAD':
                    last_mnem = 'BSWAP'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'CMOVNP_Fp32':
                    last_mnem = 'FCMOVNP'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'CMOVP_Fp3':
                    last_mnem = 'FCMOVP'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'CMPSDrm_Int':
                    last_mnem = 'CMPSD'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'MOVSX16rm16':
                    last_mnem = 'MOVSX'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'MOVZX16rm16':
                    last_mnem = 'MOVZX'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'ST_Fp32m':
                    last_mnem = 'FST'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'CMOVNP_Fp64':
                    last_mnem = 'FCMOVNU'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'CMPSDrr_Int':
                    last_mnem = 'CMPSD'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'CMPSSrm_Int':
                    last_mnem = 'CMPSS'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'VCMPSDrm_Int':
                    last_mnem = 'VCMPSD'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'VCMPSSrm_Int':
                    last_mnem = 'VCMPSS'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'VPCMOVYrrr_REV':
                    last_mnem = 'VPCMOV'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'VRNDSCALESDZm':
                    last_mnem = 'VRNDSCALESD'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'VRNDSCALESSZm':
                    last_mnem = 'VRNDSCALESS'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'VMAXCPDZ128rm':
                    last_mnem = 'VMAXPD'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'VMAXCPSZ128rm':
                    last_mnem = 'VMAXPS'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'VMAXCSDZrm':
                    last_mnem = 'VMAXSD'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'VMAXCSSZrm':
                    last_mnem = 'VMAXSS'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'VMINCPDZ128rm':
                    last_mnem = 'VMINPD'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'VMINCPSZ128rm':
                    last_mnem = 'VMINPS'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'VMINCSDZrm':
                    last_mnem = 'VMINSD'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'VMINCSSZrm':
                    last_mnem = 'VMINSS'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'VMOV64toPQIZrm':
                    last_mnem = 'VMOVQ'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'VPERMIL2PDYrr_REV':
                    last_mnem = 'VPERMILPD'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'VPERMIL2PSYrr_REV':
                    last_mnem = 'VPERMILPS'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'VCVTSD2SI64Zrm_Int':
                    last_mnem = 'VCVTSD2SI'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn == 'VCVTSD2SSrm_Int':
                    last_mnem = 'VCVTSD2SS'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn ==    'VCVTSS2SI64Zrm_Int':
                    last_mnem = 'VCVTSS2SI'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn ==    'VCVTTSD2SI64Zrm_Int':
                    last_mnem = 'VCVTTSD2SI'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)
                elif insn ==    'VCVTTSS2SI64Zrm_Int':
                    last_mnem = 'VCVTTSS2SI'
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)

                elif insn.startswith('VFMSUBADD'):
                    if insn[len('VFMSUBADD')].isdigit():
                        last_mnem = insn[:len('VFMSUBADD123xy')]
                    else:
                        last_mnem = insn[:len('VFMSUBADDSS')]
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)

                elif insn.startswith('VFMADDSUB'):
                    if insn[len('VFMADDSUB')].isdigit():
                        last_mnem = insn[:len('VFMADDSUB123xy')]
                    else:
                        last_mnem = insn[:len('VFMADDSUBSS')]
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)

                elif insn.startswith('VFMADD'):
                    if insn[len('VFMADD')].isdigit():
                        last_mnem = insn[:len('VFMADD123PD')]
                    else:
                        last_mnem = insn[:len('VFMADDPD')]
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)

                elif insn.startswith('VFMSUB'):
                    if insn[len('VFMSUB')].isdigit():
                        last_mnem = insn[:len('VFMSUB123PD')]
                    else:
                        last_mnem = insn[:len('VFMSUBPD')]
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)

                elif insn.startswith('VFNMADD'):
                    if insn[len('VFNMADD')].isdigit():
                        last_mnem = insn[:len('VFNMADD123xy')]
                    else:
                        last_mnem = insn[:len('VFNMADDSS')]
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)

                elif insn.startswith('VFNMSUB'):
                    if insn[len('VFNMSUB')].isdigit():
                        last_mnem = insn[:len('VFNMSUB123xy')]
                    else:
                        last_mnem = insn[:len('VFNMSUBSS')]
                    print_entry(arch.upper(), insn, last_mnem, mapping, False)

                elif insn in insn_id_list:
                    # trust old mapping table
                    last_mnem = insn_id_list[insn].upper()
                    print_entry(arch.upper(), insn, insn_id_list[insn].upper(), mapping, False)
                else:
                    # the last option when we cannot find mnem: use the last good mnem
                    print_entry(arch.upper(), insn, last_mnem, mapping, True)

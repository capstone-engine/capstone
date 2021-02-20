#!/usr/bin/python
# convert LLVM GenSystemRegister.inc for Capstone disassembler.
# by Nguyen Anh Quynh, 2019

import sys

if len(sys.argv) == 1:
    print("Syntax: %s <GenSystemRegister.inc>" %sys.argv[0])
    sys.exit(1)

f = open(sys.argv[1])
lines = f.readlines()
f.close()

#arch = sys.argv[2].upper()

print("""
/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* GenSystemRegister Source Fragment                                          *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

""")

# extract BankedRegValues enum
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'enum BankedRegValues {':
        count += 1
        print(line.strip())
        continue

    line = line.strip()
    if count == 1:
        if line == '};':
            # done with first enum
            break
        else:
            # skip pseudo instructions
            print("\t%s" %(line))

print('};\n')

# extract MClassSysRegsList
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'MClassSysRegsList[]' in line:
        count += 1
        print('static const MClassSysReg MClassSysRegsList[] = {')
        continue

    if count == 1:
        if line.strip() == '};':
            # done with first enum
            break
        else:
            # enum items
            # { "apsr_g", 0x400, 0x0, 0x400,  {ARM::FeatureDSP}  }, // 0
            line2 = line.replace('::', '_')
            sysreg = line2[line2.index('"') + 1 : line2.index('",')]
            tmp = line2.split(',')
            print("%s, ARM_SYSREG_%s%s" %(line2[:line2.index('",') + 1], sysreg.upper(), line2[line2.index('",') + 1 :]))

print('};\n')

# extract BankedRegsList
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'BankedRegsList[]' in line:
        count += 1
        print('static const BankedReg BankedRegsList[] = {')
        continue

    if count == 1:
        if line.strip() == '};':
            # done with first enum
            break
        else:
            # enum items
            line2 = line.replace('::', '_')
            sysreg = line2[line2.index('"') + 1 : line2.index('",')]
            tmp = line2.split(',')
            print("%s, ARM_SYSREG_%s%s" %(line2[:line2.index('",') + 1], sysreg.upper(), line2[line2.index('",') + 1 :]))

print('};\n')

# lookupMClassSysRegByM2M3Encoding8
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'lookupMClassSysRegByM2M3Encoding8' in line and '{' in line:
        count += 1
        print('const MClassSysReg *lookupMClassSysRegByM2M3Encoding8(uint16_t encoding)\n{')
        print('  unsigned int i;')
        continue

    if count == 1 and 'IndexType Index[] = {' in line:
        count += 1

    if count == 2:
        if line.strip() == '};':
            # done with array, or this function?
            print(line)
            break
        else:
            # enum items
            print(line)

print("""
  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), encoding);
  if (i == -1)
    return NULL;
  else
    return &MClassSysRegsList[Index[i].index];
}
""")


# lookupMClassSysRegByM1Encoding12
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'lookupMClassSysRegByM1Encoding12' in line and '{' in line:
        count += 1
        print('const MClassSysReg *lookupMClassSysRegByM1Encoding12(uint16_t encoding)\n{')
        print('  unsigned int i;')
        continue

    if count == 1 and 'IndexType Index[] = {' in line:
        count += 1

    if count == 2:
        if line.strip() == '};':
            # done with array, or this function?
            print(line)
            break
        else:
            # enum items
            print(line)

print("""
  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), encoding);
  if (i == -1)
    return NULL;
  else
    return &MClassSysRegsList[Index[i].index];
}
""")

# lookupBankedRegByEncoding
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'lookupBankedRegByEncoding' in line and '{' in line:
        count += 1
        print('const BankedReg *lookupBankedRegByEncoding(uint8_t encoding)\n{')
        print('  unsigned int i;')
        continue

    if count == 1 and 'IndexType Index[] = {' in line:
        count += 1

    if count == 2:
        if line.strip() == '};':
            # done with array, or this function?
            print(line)
            break
        else:
            # enum items
            print(line)

print("""
  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), encoding);
  if (i == -1)
    return NULL;
  else
    return &BankedRegsList[Index[i].index];
}
""")


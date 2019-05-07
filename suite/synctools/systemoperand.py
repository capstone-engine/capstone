#!/usr/bin/python
# convert LLVM GenSystemOperands.inc of AArch64 for Capstone disassembler.
# by Nguyen Anh Quynh, 2019

import sys

if len(sys.argv) == 1:
    print("Syntax: %s <GenSystemOperands.inc> <GenSystemOperands.inc> <GenSystemOperands_enum.inc>" %sys.argv[0])
    sys.exit(1)

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

# extract PStateValues enum
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'enum PStateValues {':
        count += 1
        f2.write(line.strip() + "\n")
        continue

    line = line.strip()
    if count == 1:
        if line == '};':
            # done with first enum
            f2.write(line + "\n")
            f2.write("\n")
            break
        else:
            # skip pseudo instructions
            f2.write("  AArch64PState_%s\n" %(line))

def print_line(line):
    f1.write(line + "\n")

# extract ExactFPImmValues enum
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'enum ExactFPImmValues {':
        count += 1
        f2.write(line.strip() + "\n")
        continue

    line = line.strip()
    if count == 1:
        if line == '};':
            # done with first enum
            f2.write(line + "\n")
            f2.write("\n")
            break
        else:
            # skip pseudo instructions
            f2.write("  AArch64ExactFPImm_%s\n" %(line))

# extract ATsList[]
count = 0
c = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'const AT ATsList[] = {':
        count += 1
        print_line('static const AT ATsList[] = {')
        continue

    line = line.strip()
    if count == 1:
        if line == '};':
            # done with first enum
            print_line('};\n')
            break
        else:
            # skip pseudo instructions
            line = line.replace('::', '_')
            #line = line.replace('{}', '{ 0 }')
            line = line.replace('{}', '')
            tmp = line.split(',')
            print_line("  %s, %s }, // %u" %(tmp[0].lower(), tmp[1], c))
            c += 1

# lookupATByEncoding
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'lookupATByEncoding' in line and '{' in line:
        count += 1
        print_line('const AT *lookupATByEncoding(uint16_t Encoding)\n{')
        print_line('  unsigned int i;')
        continue

    if count == 1 and 'IndexType Index[] = {' in line:
        count += 1

    if count == 2:
        if line.strip() == '};':
            # done with array, or this function?
            print_line(line)
            break
        else:
            # enum items
            print_line(line)

print_line("""
  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &ATsList[Index[i].index];
}
""")


# extract DBsList[]
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'const DB DBsList[] = {':
        count += 1
        print_line('static const DB DBsList[] = {')
        continue

    line = line.strip()
    if count == 1:
        if line == '};':
            # done with first enum
            print_line('};\n')
            break
        else:
            # skip pseudo instructions
            line = line.replace('::', '_')
            #line = line.replace('{}', '{ 0 }')
            line = line.replace('{}', '')
            print_line("  %s" %(line))

# lookupDBByEncoding
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'lookupDBByEncoding' in line and '{' in line:
        count += 1
        print_line('const DB *lookupDBByEncoding(uint16_t Encoding)\n{')
        print_line('  unsigned int i;')
        continue

    if count == 1 and 'IndexType Index[] = {' in line:
        count += 1

    if count == 2:
        if line.strip() == '};':
            # done with array, or this function?
            print_line(line)
            break
        else:
            # enum items
            print_line(line)

print_line("""
  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &DBsList[Index[i].index];
}
""")


# extract DCsList[]
count = 0
c = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'const DC DCsList[] = {':
        count += 1
        print_line('static const DC DCsList[] = {')
        continue

    line = line.strip()
    if count == 1:
        if line == '};':
            # done with first enum
            print_line('};\n')
            break
        else:
            # skip pseudo instructions
            line = line.replace('::', '_')
            #line = line.replace('{}', '{ 0 }')
            line = line.replace('{}', '')
            tmp = line.split(',')
            print_line("  %s, %s }, // %u" %(tmp[0].lower(), tmp[1], c))
            c += 1

# lookupDCByEncoding
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'lookupDCByEncoding' in line and '{' in line:
        count += 1
        print_line('const DC *lookupDCByEncoding(uint16_t Encoding)\n{')
        print_line('  unsigned int i;')
        continue

    if count == 1 and 'IndexType Index[] = {' in line:
        count += 1

    if count == 2:
        if line.strip() == '};':
            # done with array, or this function?
            print_line(line)
            break
        else:
            # enum items
            print_line(line)

print_line("""
  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &DCsList[Index[i].index];
}
""")


# extract ICsList
count = 0
c = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'const IC ICsList[] = {':
        count += 1
        print_line('static const IC ICsList[] = {')
        continue

    line = line.strip()
    if count == 1:
        if line == '};':
            # done with first enum
            print_line('};\n')
            break
        else:
            # skip pseudo instructions
            line = line.replace('::', '_')
            #line = line.replace('{}', '{ 0 }')
            line = line.replace('{}', '')
            #tmp = line.split(',')
            #print_line("  %s, %s }, // %u" %(tmp[0].lower(), tmp[1], c))
            print_line("  %s" %line.lower())
            c += 1

# lookupICByEncoding
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'lookupICByEncoding' in line and '{' in line:
        count += 1
        print_line('const IC *lookupICByEncoding(uint16_t Encoding)\n{')
        print_line('  unsigned int i;')
        continue

    if count == 1 and 'IndexType Index[] = {' in line:
        count += 1

    if count == 2:
        if line.strip() == '};':
            # done with array, or this function?
            print_line(line)
            break
        else:
            # enum items
            print_line(line)

print_line("""
  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &ICsList[Index[i].index];
}
""")


# extract TLBIsList
count = 0
c = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'const TLBI TLBIsList[] = {':
        count += 1
        print_line('static const TLBI TLBIsList[] = {')
        continue

    line = line.strip()
    if count == 1:
        if line == '};':
            # done with first enum
            print_line('};\n')
            break
        else:
            # skip pseudo instructions
            line = line.replace('::', '_')
            #line = line.replace('{}', '{ 0 }')
            line = line.replace('{}', '')
            tmp = line.split(',')
            print_line("  %s, %s, %s }, // %u" %(tmp[0].lower(), tmp[1], tmp[2], c))
            #print_line("  %s" %line.lower())
            c += 1

# lookupTLBIByEncoding
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'lookupTLBIByEncoding' in line and '{' in line:
        count += 1
        print_line('const TLBI *lookupTLBIByEncoding(uint16_t Encoding)\n{')
        print_line('  unsigned int i;')
        continue

    if count == 1 and 'IndexType Index[] = {' in line:
        count += 1

    if count == 2:
        if line.strip() == '};':
            # done with array, or this function?
            print_line(line)
            break
        else:
            # enum items
            print_line(line)

print_line("""
  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &TLBIsList[Index[i].index];
}
""")

# extract SVEPRFMsList
count = 0
c = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'const SVEPRFM SVEPRFMsList[] = {':
        count += 1
        print_line('static const SVEPRFM SVEPRFMsList[] = {')
        continue

    line = line.strip()
    if count == 1:
        if line == '};':
            # done with first enum
            print_line('};\n')
            break
        else:
            # skip pseudo instructions
            line = line.replace('::', '_')
            #line = line.replace('{}', '{ 0 }')
            line = line.replace('{}', '')
            tmp = line.split(',')
            print_line("  %s, %s }, // %u" %(tmp[0].lower(), tmp[1], c))
            #print_line("  %s" %line.lower())
            c += 1

# lookupSVEPRFMByEncoding
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'lookupSVEPRFMByEncoding' in line and '{' in line:
        count += 1
        print_line('const SVEPRFM *lookupSVEPRFMByEncoding(uint16_t Encoding)\n{')
        print_line('  unsigned int i;')
        continue

    if count == 1 and 'IndexType Index[] = {' in line:
        count += 1

    if count == 2:
        if line.strip() == '};':
            # done with array, or this function?
            print_line(line)
            break
        else:
            # enum items
            print_line(line)

print_line("""
  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &SVEPRFMsList[Index[i].index];
}
""")


# extract PRFMsList
count = 0
c = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'const PRFM PRFMsList[] = {':
        count += 1
        print_line('static const PRFM PRFMsList[] = {')
        continue

    line = line.strip()
    if count == 1:
        if line == '};':
            # done with first enum
            print_line('};\n')
            break
        else:
            # skip pseudo instructions
            line = line.replace('::', '_')
            #line = line.replace('{}', '{ 0 }')
            line = line.replace('{}', '')
            #tmp = line.split(',')
            #print_line("  %s, %s }, // %u" %(tmp[0].lower(), tmp[1], c))
            print_line("  %s" %line.lower())
            c += 1

# lookupPRFMByEncoding
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'lookupPRFMByEncoding' in line and '{' in line:
        count += 1
        print_line('const PRFM *lookupPRFMByEncoding(uint16_t Encoding)\n{')
        print_line('  unsigned int i;')
        continue

    if count == 1 and 'IndexType Index[] = {' in line:
        count += 1

    if count == 2:
        if line.strip() == '};':
            # done with array, or this function?
            print_line(line)
            break
        else:
            # enum items
            print_line(line)

print_line("""
  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &PRFMsList[Index[i].index];
}
""")


# extract PSBsList
count = 0
c = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'const PSB PSBsList[] = {':
        count += 1
        print_line('static const PSB PSBsList[] = {')
        continue

    line = line.strip()
    if count == 1:
        if line == '};':
            # done with first enum
            print_line('};\n')
            break
        else:
            # skip pseudo instructions
            line = line.replace('::', '_')
            #line = line.replace('{}', '{ 0 }')
            line = line.replace('{}', '')
            #tmp = line.split(',')
            #print_line("  %s, %s }, // %u" %(tmp[0].lower(), tmp[1], c))
            print_line("  %s" %line.lower())
            c += 1

# lookupPSBByEncoding
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'lookupPSBByEncoding' in line and '{' in line:
        count += 1
        print_line('const PSB *AArch64PSBHint_lookupPSBByEncoding(uint16_t Encoding)\n{')
        print_line('  unsigned int i;')
        continue

    if count == 1 and 'IndexType Index[] = {' in line:
        count += 1

    if count == 2:
        if line.strip() == '};':
            # done with array, or this function?
            print_line(line)
            break
        else:
            # enum items
            print_line(line)

print_line("""
  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &PSBsList[Index[i].index];
}
""")


# extract ISBsList
count = 0
c = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'const ISB ISBsList[] = {':
        count += 1
        print_line('static const ISB ISBsList[] = {')
        continue

    line = line.strip()
    if count == 1:
        if line == '};':
            # done with first enum
            print_line('};\n')
            break
        else:
            # skip pseudo instructions
            line = line.replace('::', '_')
            #line = line.replace('{}', '{ 0 }')
            line = line.replace('{}', '')
            #tmp = line.split(',')
            #print_line("  %s, %s }, // %u" %(tmp[0].lower(), tmp[1], c))
            print_line("  %s" %line.lower())
            c += 1

# lookupISBByName
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'lookupISBByEncoding' in line and '{' in line:
        count += 1
        print_line('const ISB *lookupISBByEncoding(uint16_t Encoding)\n{')
        print_line('  unsigned int i;')
        continue

    if count == 1 and 'IndexType Index[] = {' in line:
        count += 1

    if count == 2:
        if line.strip() == '};':
            # done with array, or this function?
            print_line(line)
            break
        else:
            # enum items
            print_line(line)

print_line("""
  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &ISBsList[Index[i].index];
}
""")


# extract TSBsList
count = 0
c = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'const TSB TSBsList[] = {':
        count += 1
        print_line('static const TSB TSBsList[] = {')
        continue

    line = line.strip()
    if count == 1:
        if line == '};':
            # done with first enum
            print_line('};\n')
            break
        else:
            # skip pseudo instructions
            line = line.replace('::', '_')
            #line = line.replace('{}', '{ 0 }')
            line = line.replace('{}', '')
            tmp = line.split(',')
            print_line("  %s, %s }, // %u" %(tmp[0].lower(), tmp[1], c))
            #print_line("  %s" %line.lower())
            c += 1

# lookupTSBByEncoding
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'lookupTSBByEncoding' in line and '{' in line:
        count += 1
        print_line('const TSB *lookupTSBByEncoding(uint16_t Encoding)\n{')
        continue

    if count == 1 and 'IndexType Index[] = {' in line:
        count += 1

    if count == 2:
        if line.strip() == '};':
            # done with array, or this function?
            print_line(line)
            break
        else:
            # enum items
            print_line(line)

print_line("""
  if (Encoding >= ARR_SIZE(TSBsList))
    return NULL;
  else
    return &TSBsList[Index[Encoding].index];
}
""")


# extract SysRegsList
count = 0
c = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'const SysReg SysRegsList[] = {':
        count += 1
        print_line('static const SysReg SysRegsList[] = {')
        continue

    line = line.strip()
    if count == 1:
        if line == '};':
            # done with first enum
            print_line('};\n')
            break
        else:
            # skip pseudo instructions
            line = line.replace('::', '_')
            #line = line.replace('{}', '{ 0 }')
            line = line.replace('{}', '')
            tmp = line.split(',')
            print_line("  %s, %s, %s, %s }, // %u" %(tmp[0].lower(), tmp[1], tmp[2], tmp[3], c))
            #print_line("  %s" %line.lower())
            c += 1

# lookupSysRegByEncoding
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'lookupSysRegByEncoding' in line and '{' in line:
        count += 1
        print_line('const SysReg *lookupSysRegByEncoding(uint16_t Encoding)\n{')
        print_line('  unsigned int i;')
        continue

    if count == 1 and 'IndexType Index[] = {' in line:
        count += 1

    if count == 2:
        if line.strip() == '};':
            # done with array, or this function?
            print_line(line)
            break
        else:
            # enum items
            print_line(line)

print_line("""
  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &SysRegsList[Index[i].index];
}
""")

# extract PStatesList
count = 0
c = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'const PState PStatesList[] = {':
        count += 1
        print_line('static const PState PStatesList[] = {')
        continue

    line = line.strip()
    if count == 1:
        if line == '};':
            # done with first enum
            print_line('};\n')
            break
        else:
            # skip pseudo instructions
            line = line.replace('::', '_')
            #line = line.replace('{}', '{ 0 }')
            line = line.replace('{}', '')
            tmp = line.split(',')
            print_line("  %s, %s }, // %u" %(tmp[0].lower(), tmp[1], c))
            #print_line("  %s" %line.lower())
            c += 1

# lookupPStateByEncoding
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'lookupPStateByEncoding' in line and '{' in line:
        count += 1
        print_line('const PState *lookupPStateByEncoding(uint16_t Encoding)\n{')
        print_line('  unsigned int i;')
        continue

    if count == 1 and 'IndexType Index[] = {' in line:
        count += 1

    if count == 2:
        if line.strip() == '};':
            # done with array, or this function?
            print_line(line)
            break
        else:
            # enum items
            print_line(line)

print_line("""
  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &PStatesList[Index[i].index];
}
""")

# extract SVEPREDPATsList
count = 0
c = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'const SVEPREDPAT SVEPREDPATsList[] = {':
        count += 1
        print_line('static const SVEPREDPAT SVEPREDPATsList[] = {')
        continue

    line = line.strip()
    if count == 1:
        if line == '};':
            # done with first enum
            print_line('};\n')
            break
        else:
            # skip pseudo instructions
            line = line.replace('::', '_')
            #line = line.replace('{}', '{ 0 }')
            line = line.replace('{}', '')
            tmp = line.split(',')
            #print_line("  %s, %s }, // %u" %(tmp[0].lower(), tmp[1], c))
            print_line("  %s" %line.lower())
            c += 1

# lookupSVEPREDPATByEncoding
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'lookupSVEPREDPATByEncoding' in line and '{' in line:
        count += 1
        print_line('const SVEPREDPAT *lookupSVEPREDPATByEncoding(uint16_t Encoding)\n{')
        print_line('  unsigned int i;')
        continue

    if count == 1 and 'IndexType Index[] = {' in line:
        count += 1

    if count == 2:
        if line.strip() == '};':
            # done with array, or this function?
            print_line(line)
            break
        else:
            # enum items
            print_line(line)

print_line("""
  i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
  if (i == -1)
    return NULL;
  else
    return &SVEPREDPATsList[Index[i].index];
}
""")


# extract ExactFPImmsList
count = 0
c = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'const ExactFPImm ExactFPImmsList[] = {':
        count += 1
        print_line('static const ExactFPImm ExactFPImmsList[] = {')
        continue

    line = line.strip()
    if count == 1:
        if line == '};':
            # done with first enum
            print_line('};\n')
            break
        else:
            # skip pseudo instructions
            line = line.replace('::', '_')
            #line = line.replace('{}', '{ 0 }')
            line = line.replace('{}', '')
            tmp = line.split(',')
            #print_line("  %s, %s }, // %u" %(tmp[0].lower(), tmp[1], c))
            print_line("  %s" %line.lower())
            c += 1

# lookupExactFPImmByEnum
count = 0
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'lookupExactFPImmByEnum' in line and '{' in line:
        count += 1
        print_line('const ExactFPImm *lookupExactFPImmByEnum(uint16_t Encoding)\n{')
        continue

    if count == 1 and 'IndexType Index[] = {' in line:
        count += 1

    if count == 2:
        if line.strip() == '};':
            # done with array, or this function?
            print_line(line)
            break
        else:
            # enum items
            print_line(line)

print_line("""
  if (Encoding >= ARR_SIZE(ExactFPImmsList))
    return NULL;
  else
    return &ExactFPImmsList[Index[Encoding].index];
}
""")


#!/usr/bin/python
# convert LLVM GenRegisterInfo.inc for Capstone disassembler.
# by Nguyen Anh Quynh, 2019

import sys

if len(sys.argv) == 1:
    print("Syntax: %s <GenRegisterInfo.inc> <architecture>" %sys.argv[0])
    sys.exit(1)

f = open(sys.argv[1])
lines = f.readlines()
f.close()

arch = sys.argv[2]

print("""
/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\\
|*                                                                            *|
|* Target Register Enum Values                                                *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GET_REGINFO_ENUM
#undef GET_REGINFO_ENUM
""")

enum_count = 0

# 1st enum is register enum
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'enum {':
        enum_count += 1
        print(line)
        continue

    if enum_count == 1:
        if line.strip() == '};':
            print(line)
            # done with first enum
            break
        else:
            # enum items
            print("  %s_%s" %(arch, line.strip()))

# 2nd enum is register class
enum_count = 0
print("\n// Register classes")
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'enum {':
        enum_count += 1
        if enum_count == 2:
            print(line)
        continue

    if enum_count == 2:
        if line.strip() == '};':
            # done with 2nd enum
            print(line.strip())
            break
        else:
            # enum items
            print("  %s_%s" %(arch, line.strip()))

if arch.upper() == 'ARM':
    # 3rd enum is Subregister indices
    enum_count = 0
    print("\n// Subregister indices")
    for line in lines:
        line = line.rstrip()
    
        if len(line.strip()) == 0:
            continue
    
        if line.strip() == 'enum {':
            enum_count += 1
            if enum_count == 3:
                print(line)
            continue
    
        if enum_count == 3:
            if line.strip() == '};':
                # done with 2nd enum
                print(line.strip())
                break
            else:
                # enum items
                print("  %s_%s" %(arch, line.strip()))

if arch.upper() == 'AARCH64':
    # 3rd enum is Register alternate name indices
    enum_count = 0
    print("\n// Register alternate name indices")
    for line in lines:
        line = line.rstrip()
    
        if len(line.strip()) == 0:
            continue
    
        if line.strip() == 'enum {':
            enum_count += 1
            if enum_count == 3:
                print(line)
            continue
    
        if enum_count == 3:
            if line.strip() == '};':
                # done with 2nd enum
                print(line.strip())
                break
            else:
                # enum items
                print("  %s_%s" %(arch, line.strip()))

    # 4th enum is Subregister indices
    enum_count = 0
    print("\n// Subregister indices")
    for line in lines:
        line = line.rstrip()
    
        if len(line.strip()) == 0:
            continue
    
        if line.strip() == 'enum {' or 'enum :' in line.strip():
            enum_count += 1
            if enum_count == 4:
                print('enum {')
            continue
    
        if enum_count == 4:
            if line.strip() == '};':
                # done with 2nd enum
                print(line.strip())
                break
            else:
                # enum items
                print("  %s_%s" %(arch, line.strip()))

# end of enum
print("")
print("#endif // GET_REGINFO_ENUM")

print("""
#ifdef GET_REGINFO_MC_DESC
#undef GET_REGINFO_MC_DESC

""")

# extract RegDiffLists
finding_struct = True
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if arch + 'RegDiffLists' in line:
        finding_struct = False
        print("static const MCPhysReg " + arch + "RegDiffLists[] = {")
        continue

    if finding_struct:
        continue
    else:
        print(line)
        if line == '};':
            # done with this struct
            print("")
            break

# extract SubRegIdxLists
finding_struct = True
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if arch + 'SubRegIdxLists' in line:
        finding_struct = False
        print("static const uint16_t " + arch + "SubRegIdxLists[] = {")
        continue

    if finding_struct:
        continue
    else:
        print(line)
        if line == '};':
            # done with this struct
            print("")
            break

# extract RegDesc
finding_struct = True
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if arch + 'RegDesc' in line:
        finding_struct = False
        print("static const MCRegisterDesc " + arch + "RegDesc[] = {")
        continue

    if finding_struct:
        continue
    else:
        print(line)
        if line == '};':
            # done with this struct
            print("")
            break

# extract register classes
finding_struct = True
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'Register classes' in line and 'namespace' in line:
        finding_struct = False
        continue

    if finding_struct:
        continue
    else:
        if 'const' in line:
            line2 = line.replace('const', 'static const')
            print(line2)
        elif '::' in line:
            line2 = line.replace('::', '_')
            print(line2)
        elif 'end anonymous namespace' in line:
            # done with this struct
            break
        else:
            print(line)

print("\n")

# extract MCRegisterClasses
finding_struct = True
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if 'MCRegisterClass ' + arch + 'MCRegisterClasses[] = {' in line:
        finding_struct = False
        print("static const MCRegisterClass " + arch + "MCRegisterClasses[] = {")
        continue

    if finding_struct:
        continue
    else:
        if line == '};':
            # done with this struct
            print('};\n')
            break
        elif '::' in line:
            line = line.replace('::', '_')

        # { GR8, GR8Bits, 130, 20, sizeof(GR8Bits), X86_GR8RegClassID, 1, 1, 1, 1 },
        tmp = line.split(',')
        print("  %s, %s, %s }," %(tmp[0].strip(), tmp[1].strip(), tmp[4].strip()))

print("#endif // GET_REGINFO_MC_DESC")

#!/usr/bin/python
# convert LLVM GenSubtargetInfo.inc for Capstone disassembler.
# by Nguyen Anh Quynh, 2019

import sys

if len(sys.argv) == 1:
    print("Syntax: %s <GenSubtargetInfo.inc> <architecture>" %sys.argv[0])
    sys.exit(1)

f = open(sys.argv[1])
lines = f.readlines()
f.close()

arch = sys.argv[2]

print("""
/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Subtarget Enumeration Source Fragment                                      *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

""")

count = 0

# 1st enum is subtarget enum
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'enum {':
        count += 1
        print(line)
        continue

    if count == 1:
        if line.strip() == '};':
            # done with first enum
            break
        else:
            # enum items
            print("  %s_%s" %(arch, line.strip()))

print('};\n')

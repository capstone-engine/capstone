#!/usr/bin/python
# convert LLVM GenDisassemblerTables.inc for Capstone disassembler.
# for X86, this separate ContextDecision tables into another file
# by Nguyen Anh Quynh, 2019

import sys

if len(sys.argv) == 1:
    print("Syntax: %s <GenDisassemblerTables.inc> <X86GenDisassemblerTables.inc> <X86GenDisassemblerTables2.inc>" %sys.argv[0])
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

# static const struct ContextDecision x86DisassemblerOneByteOpcodes = {

# static const struct ContextDecision x86DisassemblerXOP8Opcodes = {

write_to_f2 = False

for line in lines:
    if 'ContextDecision x86DisassemblerOneByteOpcodes = {' in line:
        # done with f1, start writing to f2
        write_to_f2 = True

    if write_to_f2:
        f2.write(line)
    else:
        f1.write(line)

f1.close()
f2.close()

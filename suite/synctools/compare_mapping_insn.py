#!/usr/bin/python
# compare instructions in 2 files of MappingInsn.inc
# find instructions in MappingInsn1, that does not exist in MappingInsn2
# by Nguyen Anh Quynh, 2019

import sys

if len(sys.argv) == 1:
    print("Syntax: %s <MappingInsn1.inc> <MappingInsn2.inc>" %sys.argv[0])
    sys.exit(1)

f = open(sys.argv[1])
mapping1 = f.readlines()
f.close()

f = open(sys.argv[2])
mapping2 = f.readlines()
f.close()

insn1 = []
for line in mapping1:
    if 'X86_INS_' in line:
        tmp = line.split(',')
        insn_id = tmp[0].strip()
        insn1.append(insn_id)

insn2 = []
for line in mapping2:
    if 'X86_INS_' in line:
        tmp = line.split(',')
        insn_id = tmp[0].strip()
        insn2.append(insn_id)

for insn_id in insn1:
    if not insn_id in insn2:
        print("instruction %s is not in list 2" %insn_id)



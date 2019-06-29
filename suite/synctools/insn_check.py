#!/usr/bin/python
# check MappingInsn.inc to find potential incorrect mapping - for Capstone disassembler.
# by Nguyen Anh Quynh, 2019

import sys

if len(sys.argv) == 1:
    print("Syntax: %s <MappingInsn.inc>" %sys.argv[0])
    sys.exit(1)

#    ARM_CMPri, ARM_INS_CMN,
f = open(sys.argv[1])
lines = f.readlines()
f.close()

for line in lines:
    if '_INS_' in line:
        tmp = line.strip().split(',')
        if len(tmp) == 3 and tmp[2] == '':
            id_private = tmp[0].strip()
            id_public = tmp[1].strip()
            pos = id_public.find('_INS_')
            mnem = id_public[pos + len('_INS_'):]
            if not mnem in id_private:
                print("%s -> %s" %(id_private, id_public))

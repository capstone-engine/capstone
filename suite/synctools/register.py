#!/usr/bin/python
# print out all registers from LLVM GenRegisterInfo.inc for Capstone disassembler.
# NOTE: the list then must be filtered, manually.
# by Nguyen Anh Quynh, 2019

import sys

if len(sys.argv) == 1:
    print("Syntax: %s <GenRegisterInfo.inc> <architecture>" %sys.argv[0])
    sys.exit(1)

f = open(sys.argv[1])
lines = f.readlines()
f.close()

arch = sys.argv[2].upper()

enum_count = 0

# 1st enum is register enum
for line in lines:
    line = line.rstrip()

    if len(line.strip()) == 0:
        continue

    if line.strip() == 'enum {':
        enum_count += 1
        continue

    if enum_count == 1:
        if line == '};':
            # done with first enum
            break
        else:
            # enum items
            if 'NoRegister' in line or 'TARGET_REGS' in line:
                continue
            reg = line.strip().split('=')[0].strip()
            if reg.startswith('H') or reg.endswith('PH') or or reg.endswith('IH') or or reg.endswith('WH'):
                print("  %s_REG_%s = REMOVE," %(arch, reg))
            elif 'K' in reg or 'BND' in reg:
                print("  %s_REG_%s = REMOVE," %(arch, reg))
            elif reg in ('DF', 'SSP', 'R8BH', 'R9BH', 'R10BH', 'R11BH', 'R12BH', 'R13BH', 'R14BH', 'R15BH'):
                print("  %s_REG_%s = REMOVE," %(arch, reg))
            else:
                print("  %s_REG_%s," %(arch, reg))


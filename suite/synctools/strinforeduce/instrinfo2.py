#!/usr/bin/python
# convert LLVM GenInstrInfo.inc for Capstone disassembler.
# by Nguyen Anh Quynh, 2019

import sys

if len(sys.argv) == 1:
    print("Syntax: %s <GenInstrInfo.inc>" %sys.argv[0])
    sys.exit(1)


count = 0
last_line = None

f = open(sys.argv[1])
lines = f.readlines()
f.close()

# 1st enum is register enum
for line in lines:
    line = line.rstrip()

    # skip all MCPhysReg line
    if 'static const MCPhysReg ' in line:
        continue

    # skip all MCOperandInfo line
    if 'static const MCOperandInfo ' in line:
        continue

    # skip InitX86MCInstrInfo()
    if 'static inline void InitX86MCInstrInfo' in line:
        continue

    if 'II->InitMCInstrInfo' in line:
        last_line = line
        continue

    # skip the next line after II->InitMCInstrInfo
    if last_line:
        last_line = None
        continue
            

    if 'extern const MCInstrDesc ' in line:
        count += 1
        continue

    if count == 1:
        if line == '};':
            # done with first enum
            count += 1
            continue
    else:
        print(line)

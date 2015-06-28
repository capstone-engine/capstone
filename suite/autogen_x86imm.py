#!/usr/bin/python
# By Nguyen Anh Quynh, 2015
# This tool extract sizes of immediadte operands from X86 instruction names.
# Syntax: ./autogen_x86imm.py

# Gather immediate sizes to put into X86ImmSize.inc
OUTPUT = "../arch/X86/X86ImmSize.inc"

f = open("../arch/X86/X86GenInstrInfo.inc")
f2 = open(OUTPUT, "w")
for line in f.readlines():
   tmp = line.strip().split("=")
   if len(tmp) == 2:    # X86_xxx = nnn,
       name = tmp[0].strip()
       if name == "X86_INSTRUCTION_LIST_END":   # no more instructions
           break
       if name.endswith("_DB"): # pseudo instruction
           continue
       if "_LOCK_" in name or "BEXTR" in name:  # exception
           continue
       if name.startswith("X86_"):  # instruction
           if name.endswith("i8") or "i8_" in name:
               f2.write("{1, %s},\n" %name)
           elif "8ri" in name or "8mi" in name:
               f2.write("{1, %s},\n" %name)

           elif name.endswith("i16") or "i16_" in name:
               f2.write("{2, %s},\n" %name)
           elif "16ri" in name or "16mi" in name:
               f2.write("{2, %s},\n" %name)

           elif name.endswith("i32") or "i32_" in name:
               f2.write("{4, %s},\n" %name)
           elif "32ri" in name or "32mi" in name:
               f2.write("{4, %s},\n" %name)

           elif name.endswith("i64") or "i64_" in name:
               f2.write("{8, %s},\n" %name)
           elif "64ri" in name or "64mi" in name:
               f2.write("{8, %s},\n" %name)

f.close()
f2.close()

print("Generated %s" %OUTPUT)

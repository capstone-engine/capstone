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
           if name.endswith("16mi8"):
               f2.write("{2, %s},\n" %name)
           elif name.endswith("16ri8"):
               f2.write("{2, %s},\n" %name)
           elif name.endswith("32ri8"):
               f2.write("{4, %s},\n" %name)
           elif name.endswith("32mi8"):
               f2.write("{4, %s},\n" %name)
           elif name.endswith("64i32"):
               f2.write("{8, %s},\n" %name)
           elif name.endswith("64mi32"):
               f2.write("{8, %s},\n" %name)
           elif name.endswith("64ri32"):
               f2.write("{8, %s},\n" %name)
           elif name.endswith("64ri8"):
               f2.write("{8, %s},\n" %name)
           elif name.endswith("64mi8"):
               f2.write("{8, %s},\n" %name)
           elif name.endswith("16rmi8"):
               f2.write("{2, %s},\n" %name)
           elif name.endswith("32rmi8"):
               f2.write("{4, %s},\n" %name)
           elif name.endswith("16rri8"):
               f2.write("{2, %s},\n" %name)
           elif name.endswith("32rri8"):
               f2.write("{4, %s},\n" %name)
           elif name.endswith("64rmi8"):
               f2.write("{8, %s},\n" %name)
           elif name.endswith("64rmi32"):
               f2.write("{8, %s},\n" %name)
           elif name.endswith("64rri32"):
               f2.write("{8, %s},\n" %name)
           elif name.endswith("64rri8"):
               f2.write("{8, %s},\n" %name)
           elif name.endswith("32ri64"):    # special case
               f2.write("{8, %s},\n" %name)
           elif name.endswith("16i8"):    # special case
               f2.write("{2, %s},\n" %name)
           elif name.endswith("32i8"):    # special case
               f2.write("{4, %s},\n" %name)
           elif name.endswith("64i16"):    # special case
               f2.write("{8, %s},\n" %name)
           elif name.endswith("64i8"):    # special case
               f2.write("{8, %s},\n" %name)

           elif name.endswith("i8") or "i8_" in name:
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

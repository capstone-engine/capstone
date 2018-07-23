#!/bin/sh

# This script test all architectures by default.

find MC/ -name *.cs | ./disasm_mc.py

# To test just one architecture, specify the corresponsing dir:
# $ find MC/X86 -name *.cs | ./disasm_mc.py

# To test just one input file, run disasm_mc.py with that file:
# $ ./disasm_mc.py MC/X86/x86-32-fma3.s.cs

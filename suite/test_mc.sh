#!/bin/sh

# This script test all architectures by default.
# At the output are all the mismatches between Capstone (CS) & LLVM (MC).
# While most differences coming from the fact that Capstone uses more friendly
# number format, some mismatches might be because Capstone is based on older
# version of LLVM (which should be fixed in the next release)

find MC/ -name *.cs | ./test_mc.py

# To test just one architecture, specify the corresponsing dir:
# $ find MC/X86 -name *.cs | ./test_mc.py

# To test just one input file, run test_mc.py with that file:
# $ ./test_mc.py MC/X86/x86-32-fma3.s.cs

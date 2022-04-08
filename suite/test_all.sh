#!/bin/sh

# dump test output to /tmp/<name> for diffing
# this is useful to detect if a change modifies any disasm output

# syntax: test_all.sh <name>

# ./test_archs.py > /tmp/$1_arch
./test_c.sh $1_c

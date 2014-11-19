#!/bin/bash

# Run all the Python tests, and send the output that to a file to be compared later
# This is useful when we want to verify if a commit (wrongly) changes the disassemble result.

../bindings/python/test.py > /tmp/$1
../bindings/python/test_detail.py >> /tmp/$1
../bindings/python/test_arm.py >> /tmp/$1
../bindings/python/test_arm64.py >> /tmp/$1
../bindings/python/test_mips.py >> /tmp/$1
../bindings/python/test_ppc.py >> /tmp/$1
../bindings/python/test_sparc.py >> /tmp/$1
../bindings/python/test_x86.py >> /tmp/$1

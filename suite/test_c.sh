#!/bin/bash

# Run all the Python tests, and send the output that to a file to be compared later
# This is useful when we want to verify if a commit (wrongly) changes the disassemble result.

../tests/test > /tmp/$1
../tests/test_detail >> /tmp/$1
../tests/test_skipdata >> /tmp/$1
../tests/test_iter >> /tmp/$1
../tests/test_arm >> /tmp/$1
../tests/test_arm64 >> /tmp/$1
../tests/test_mips >> /tmp/$1
../tests/test_ppc >> /tmp/$1
../tests/test_sparc >> /tmp/$1
../tests/test_x86 >> /tmp/$1
../tests/test_systemz >> /tmp/$1
../tests/test_xcore >> /tmp/$1
../tests/test_riscv >> /tmp/$1

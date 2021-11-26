#!/bin/bash

# Run all the Python tests, and send the output that to a file to be compared later
# This is useful when we want to verify if a commit (wrongly) changes the disassemble result.

../tests/test_arm > /tmp/$1
../tests/test_arm64 > /tmp/$1
../tests/test_basic > /tmp/$1
../tests/test_bpf > /tmp/$1
../tests/test_customized_mnem > /tmp/$1
../tests/test_detail > /tmp/$1
../tests/test_evm > /tmp/$1
../tests/test_iter > /tmp/$1
../tests/test_m680x > /tmp/$1
../tests/test_m68k > /tmp/$1
../tests/test_mips > /tmp/$1
../tests/test_mos65xx > /tmp/$1
../tests/test_ppc > /tmp/$1
../tests/test_skipdata > /tmp/$1
../tests/test_sparc > /tmp/$1
../tests/test_systemz > /tmp/$1
../tests/test_tms320c64x > /tmp/$1
../tests/test_wasm > /tmp/$1
../tests/test_winkernel > /tmp/$1
../tests/test_x86 > /tmp/$1
../tests/test_xcore > /tmp/$1
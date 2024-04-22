#!/bin/sh -x

cstool -d x64 0x4 | grep "ERROR: invalid assembly code" &&
cstool -d arm 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d aarch64 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d alpha 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d mips64 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d ppc64 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d sparc 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d systemz 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d xcore 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d m68k 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d tms320c64x 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d m6811 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d cpu12 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d hd6309 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d hcs08 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d evm 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d 6502 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d 65c02 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d w65c02 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d 65816 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d wasm 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d bpf 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d ebpf 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d riscv64 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d sh 0x1 | grep "ERROR: invalid assembly code" &&
cstool -d tc162 0x1 | grep "ERROR: invalid assembly code"

# One successful disassembly
cstool -d x64 0xc5,0xca,0x58,0xd4

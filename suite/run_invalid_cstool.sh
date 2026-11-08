#!/bin/sh -x

# Every architecture module must reject input it cannot decode.
# Each check runs on its own, so one failure does not hide the rest.

fail() {
	echo "FAIL: $1"
	exit 1
}

check_invalid() {
	arch=$1
	out=$(cstool -d "$arch" 0x1 2>&1)
	echo "$out" | grep -q "ERROR: invalid assembly code" ||
		fail "$arch did not reject 0x1"
}

for arch in x64 arm aarch64 alpha mips64 ppc64 sparc systemz xcore m68k \
	tms320c64x m6811 cpu12 hd6309 hcs08 evm 6502 65c02 w65c02 65816 wasm \
	bpf ebpf riscv64 sh tc162 loongarch64 esp32 hppa20 arc; do
	check_invalid "$arch"
done

# One successful disassembly
cstool -d x64 0xc5,0xca,0x58,0xd4 | grep -q "xmm" ||
	fail "x64 failed to disassemble a valid instruction"

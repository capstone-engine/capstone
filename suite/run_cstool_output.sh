#!/bin/sh
#
# Pins the text layout of cstool so it cannot drift silently.
# See https://github.com/capstone-engine/capstone/issues/2740

tmp=${TMPDIR:-/tmp}/cstool_output.$$
trap 'rm -f "$tmp" "$tmp.exp"' EXIT
failed=0

# check <description> <command...>  -- expected output is on stdin
check() {
	desc=$1
	shift
	cat > "$tmp.exp"
	if ! "$@" > "$tmp" 2>&1; then
		echo "FAIL: $desc: command failed"
		failed=1
		return
	fi
	if ! diff -u "$tmp.exp" "$tmp"; then
		echo "FAIL: $desc"
		failed=1
	fi
}

# 1. single and multiple instructions keep the offset and byte columns aligned
check 'single and multiple instructions keep the offset and byte columns aligned' cstool x64 '55 48 89 e5' <<'EOF'
 0  55                                               push	rbp
 1  48 89 e5                                         mov	rbp, rsp
EOF

# 2. a shorter instruction stream keeps the same column layout
check 'a shorter instruction stream keeps the same column layout' cstool aarch64 '6b 29 cb 1a' <<'EOF'
 0  6b 29 cb 1a  asr	w11, w11, w11
EOF

# 3. a start address widens the offset column
check 'a start address widens the offset column' cstool x64 'c5 ca 58 d4' 0x400000 <<'EOF'
400000  c5 ca 58 d4                                      vaddss	xmm2, xmm6, xmm4
EOF

# 4. thumb mode disassembles through the same layout
check 'thumb mode disassembles through the same layout' cstool arm '1f 20 03 d5' <<'EOF'
 0  1f 20 03 d5  strle	r2, [r3, #-0x1f]
EOF

[ "$failed" -eq 0 ] || exit 1

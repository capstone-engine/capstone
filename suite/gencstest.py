#!/usr/bin/env python3

import sys
import re
import argparse
from pathlib import Path

# 80001c1a <IfxVadc_disableAccess>:
# 80001c1a:	40 4f       	mov.aa %a15,%a4
# 80001c1c:	02 48       	mov %d8,%d4
# 80001c1e:	6d ff 9d ff 	call 80001b58 <IfxScuWdt_getSafetyWatchdogPassword>

unique_set = set()


def num2prefix_hex(x, prefix="#"):
    if x.startswith("0x") or x.startswith("-0x") or x == "0":
        x = prefix + x
    if x.isdigit() or (x.startswith("-") and x[1:].isdigit()):
        x = prefix + hex(int(x))
    return x

def op2prefix_hex(x):
    x = num2prefix_hex(x)
    if "]" in x:
        xs = x.split("]")
        if xs[1].isdigit() or xs[1].startswith('-'):
            x = xs[0] + "]" + num2prefix_hex(xs[1])
    return x

def gen(filename):
    with open(filename, "r") as f:
        for line in f:
            caps = re.findall(
                r"([0-9a-f]+):\s+([0-9a-f]+) ([0-9a-f]+) ([0-9a-f]+)? ([0-9a-f]+)?\s+"
                r"(\S+) (\S+)",
                line,
            )
            if not caps:
                continue
            caps = caps[0]
            addr = int(caps[0], 16)
            hexstr = caps[1:5]
            mnemonic: str = caps[5]
            operands = caps[6]

            def try_dedisp(x):
                try:
                    disp = int(x, 16)
                    if disp > 0x80000000:
                        x = hex(disp - addr)
                    return x
                except ValueError:
                    pass
                return x

            def is_hex_string(s: str) -> bool:
                if not s.isalnum():
                    return False
                return all(c.isdigit() or c.lower() in "abcdef" for c in s) and any(
                    c.lower() in "abcdef" for c in s
                )

            hexstr = ",".join(f"0x{x}" for x in hexstr if x)
            fun = re.match(r"\s*<.+>\s*", operands)
            # print(hex(addr), hexstr, mnemonic, operands)
            if any(
                [
                    mnemonic.startswith(pre)
                    for pre in [
                        "mtcr",
                        "mfcr",
                        "st.a",
                        "st.b",
                        "st.d",
                        "st.w",
                        "ld.a",
                        "ld.b",
                        "ld.d",
                        "ld.w",
                    ]
                ]
            ):
                # unique_set.add(f"# {hexstr.ljust(19)} = {mnemonic}\t{operands}")
                continue

            ops = operands.split(",")
            if (
                any(
                    [mnemonic.startswith(pre) for pre in ["j", "call", "loop", "fcall"]]
                )
                or fun
            ):
                re.sub(r"\s*<.+>\s*", "", operands)
                # de relative addressing
                ops = list(map(try_dedisp, ops))

            for i, x in enumerate(ops):
                if is_hex_string(x) and not x.startswith("0x"):
                    x = "#0x" + x
                x = op2prefix_hex(x)
                ops[i] = x

            operands = ", ".join(ops)
            operands = operands.replace("%", "")
            unique_set.add(f"{hexstr.ljust(19)} = {mnemonic}\t{operands}")

    print("# CS_ARCH_TRICORE, CS_MODE_TRICORE_162, None")
    print("\n".join(unique_set))

def att2intel(filename):
    with open(filename, "r") as fp:
        lines = []
        for line in fp.readlines():
            if not '=' in line:
                lines.append(line)
                continue
            insn = line.split('=')
            hexstr = insn[0]
            insn = insn[1]
            ops = insn.strip().split(', ')
            ops = ops[0].split('\t') + ops[1:]
            mnemonic = ops[0]
            ops = ops[1:]
            for i,op in enumerate(ops):
                op = op.strip()
                op = op2prefix_hex(op)
                ops[i] = op
            operands = ", ".join(ops)
            lines.append(f"{hexstr.ljust(19)} = {mnemonic}\t{operands}")
        print('\n'.join(lines))

def main():
    parser = argparse.ArgumentParser(description="Convert objdump's output to .s.cs test file")
    parser.add_argument('input', type=Path, help='input file path')
    parser.add_argument('--intel', action='store_true', help='convert .s.cs file to intel syntax')
    args = parser.parse_args()
    if not args.intel:
        gen(args.input)
    else:
        att2intel(args.input)


if __name__ == "__main__":
    main()

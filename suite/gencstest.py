#!/usr/bin/env python3

import sys
import re

# 80001c1a <IfxVadc_disableAccess>:
# 80001c1a:	40 4f       	mov.aa %a15,%a4
# 80001c1c:	02 48       	mov %d8,%d4
# 80001c1e:	6d ff 9d ff 	call 80001b58 <IfxScuWdt_getSafetyWatchdogPassword>

unique_set = set()


def gen(filename):
    with open(filename, 'r') as f:
        for line in f:
            caps = re.findall(r'([0-9a-f]+):\s+([0-9a-f]+) ([0-9a-f]+) ([0-9a-f]+)? ([0-9a-f]+)?\s+'
                              r'(\S+) (\S+)', line)
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
                return all(c.isdigit() or c.lower() in 'abcdef' for c in s) and any(c.lower() in 'abcdef' for c in s)

            hexstr = ','.join(f'0x{x}' for x in hexstr if x)
            fun = re.match(r'\s*<.+>\s*', operands)
            # print(hex(addr), hexstr, mnemonic, operands)
            if any([mnemonic.startswith(pre) for pre in
                    ['mtcr', 'mfcr', 'st.a', 'st.b', 'st.d', 'st.w', 'ld.a', 'ld.b', 'ld.d', 'ld.w']]):
                unique_set.add(f"# {hexstr.ljust(19)} = {mnemonic}\t{operands}")
                continue

            ops = operands.split(',')
            if any([mnemonic.startswith(pre) for pre in ['j', 'call', 'loop', 'fcall']]) or fun:
                re.sub(r'\s*<.+>\s*', '', operands)
                # de relative addressing
                ops = map(try_dedisp, ops)

            ops = map(lambda x: '0x' + x if is_hex_string(x) and not x.startswith('0x') else x, ops)
            operands = ', '.join(ops)
            unique_set.add(f"{hexstr.ljust(19)} = {mnemonic}\t{operands}")

    print('# CS_ARCH_TRICORE, CS_MODE_TRICORE_162, None')
    print('\n'.join(unique_set))


def main():
    gen(sys.argv[1])


if __name__ == '__main__':
    main()

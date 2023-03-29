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
                    if disp > 0x10000000:
                        return hex(disp - addr)
                    return x
                except ValueError:
                    pass
                return x

            hexstr = ','.join(f'0x{x}' for x in hexstr if x)
            operands = re.sub(r'\s*<.+>\s*', '', operands)
            operands = operands.replace(',', ', ')
            # print(hex(addr), hexstr, mnemonic, operands)
            key = None
            if any([mnemonic.startswith(pre) for pre in ['mtcr', 'mfcr']]):
                key = f"# {hexstr.ljust(19)} = {mnemonic}\t{operands}"
            elif any([mnemonic.startswith(pre) for pre in ['j', 'call', 'loop']]):
                # de relative addressing
                if ',' in operands:
                    operands = map(try_dedisp, operands.split(', '))
                    operands = ', '.join(operands)
                else:
                    operands = try_dedisp(operands)
                key = f"# {hexstr.ljust(19)} = {mnemonic}\t{operands}"
            else:
                key = f"{hexstr.ljust(19)} = {mnemonic}\t{operands}"
            if key in unique_set:
                continue
            unique_set.add(key)
            print(key)


def main():
    gen(sys.argv[1])


if __name__ == '__main__':
    main()

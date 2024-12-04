#!/usr/bin/env python3

import yaml
import sys

HEADER = '# CS_ARCH_ARC, CS_MODE_LITTLE_ENDIAN, None\n\n'

def main(yaml_path: str, cs_path: str):
    with open(yaml_path) as yaml_file:
        yaml_data = yaml.safe_load(yaml_file)
        
    cs_data = HEADER
    test_cases = yaml_data['test_cases']
    for case in test_cases:
        input = case['input']
        expected = case['expected']
        asm_bytes = input['bytes']
        asm_text = expected['insns'][0]['asm_text']
        cs_data += f"{','.join(map(hex, asm_bytes))} = {asm_text}\n"
    
    with open(cs_path, 'w') as cs:
        cs.write(cs_data)
    
if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
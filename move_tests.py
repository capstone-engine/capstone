#!/usr/bin/env python3

import os
import sys
import re
from pathlib import Path

def conv(h: str) -> str:
    if "," in h or " " in h:
        return h
    n = int(h, 16)
    res = ""
    while n > 0:
        res = ", 0x{:02x}".format(n % 0x100) + res
        n >>= 8

    return res.strip(", ")

def run():
    mc_path=sys.argv[1]
    print(f"MC path {mc_path}")

    yaml_tc = """  -
    input:
      bytes: [ <ENCODING> ]
      arch: "<ARCH>"
      options: [ <OPTIONS> ]
    expected:
      insns:
        -
          asm_text: "<ASM_TEXT>"
"""

    for (dirpath, dirnames, filenames) in os.walk(mc_path):
        for filename in filenames:
            if not filename.endswith(".cs"):
                continue
            with open(dirpath + "/" + filename, "r") as f:
                content = f.read()
            lines = content.splitlines()
            if not lines[0].startswith("#"):
                raise(f"{lines[0]} is not the descriptor line")
            arch, mode, opts = lines[0].split(",")
            arch = arch.strip("# ")
            mode = mode.strip(" ")
            opts = opts.strip(" ")

            n_opts = re.sub(r"[| ,+]+", ",", mode)
            n_opts += "," if n_opts else ""
            n_opts += re.sub(r"[| ,+]+", ",", opts)
            n_opts = n_opts.split(",")
            yaml_content = "test_cases:\n"

            for line in lines[1:]:
                if not line.startswith("0x"):
                    continue
                line = re.sub(r"\s?==?\s?", "=", line)
                s = line.split("=")
                if len(s) != 2:
                    print(f"malformed: {line}")
                    exit(1)
                    
                encoding = re.sub(r"[ ,]+", ", ", s[0].strip())
                encoding = conv(encoding)
                asm = re.sub(r"\s+", " ", s[1].strip())
                tc = yaml_tc
                tc = tc.replace("<ENCODING>", encoding)
                tc = tc.replace("<ARCH>", f'{arch}')
                opts = ", ".join([f'"{o}"' for o in set(n_opts) if o != "None"])
                tc = tc.replace("<OPTIONS>", opts)
                tc = tc.replace("<ASM_TEXT>", f'{asm}')
                yaml_content += tc

            out_dir = Path(sys.argv[2])
            Path.mkdir(out_dir, parents=True, exist_ok=True)
            filename = filename.replace('.cs', '.yaml')
            if "input" not in yaml_content:
                continue

            print(f"Write: {filename}")
            with open(f"{out_dir}/{filename}", "w+") as f:
                f.write(yaml_content)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"{sys.argv[0]} <in-dir> <out_dir>")
        exit(1)
    run()

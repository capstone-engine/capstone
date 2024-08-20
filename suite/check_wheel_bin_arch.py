#!/usr/bin/env python3
# Copyright © 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import logging as log
import subprocess as sp
import re
import os
import sys
from pathlib import Path

if len(sys.argv) != 2:
    print(f"{sys.argv[0]} <wheel_dir>")
    exit(-1)

log.basicConfig(
    level=log.INFO,
    stream=sys.stdout,
    format="%(levelname)-5s - %(message)s",
    force=True,
)

archs = {
    "universal2": ["x86_64", "arm64"],
    "x86_64": [r"x86[_-]64"],
    "arm64": ["arm64"],
    "aarch64": ["ARM aarch64"],
    "i686": ["Intel 80386"],
    "win32": [r"INVALID"],
    "amd64": [r"x86[_-]64"],
}

filename = {
    "macosx": "libcapstone.dylib",
    "manylinux": "libcapstone.so",
    "musllinux": "libcapstone.so",
    "win": "capstone.dll",
}

success = True
wheel_seen = False
for root, dir, files in os.walk(sys.argv[1]):
    for file in files:
        f = Path(root).joinpath(file)
        if f.suffix != ".whl":
            continue
        wheel_seen = True
        target = re.search(r"py3-none-(.+).whl", f"{f}").group(1)
        platform = re.search("^(win|manylinux|musllinux|macosx)", target).group(1)

        arch = re.search(
            "(universal2|x86_64|arm64|aarch64|i686|win32|amd64)$", target
        ).group(1)
        log.info(f"Target: {target} - Platform: {platform} - Arch: {archs[arch]}")

        out_dir = f"{platform}__{arch}"
        sp.run(["unzip", "-q", f"{f}", "-d", out_dir], check=True)
        lib_path = Path(out_dir).joinpath(f"capstone/lib/{filename[platform]}")
        result = sp.run(["file", "-b", f"{lib_path}"], capture_output=True, check=True)
        stdout = result.stdout.decode("utf8").strip()
        if any([not re.search(a, stdout) for a in archs[arch]]):
            success = False
            log.error(f"The wheel '{file}' is not compiled for '{archs[arch]}'.")
            log.error(f"Binary is: {stdout}")
            print()
        else:
            log.info(f"OK: Arch: {arch} - {lib_path}")
            log.info(f"Binary is: {stdout}")
            log.info(f"Delete {out_dir}")
            print()
        os.system(f"rm -r {out_dir}")
    break

if not wheel_seen:
    log.error("No wheel was checked.")
    exit(-1)

if not success:
    log.error("Binary files are compiled for the wrong architecture.")
    exit(-1)

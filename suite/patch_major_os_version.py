#!/usr/bin/env python
# By Nguyen Anh Quynh

import sys, struct

if len(sys.argv) < 2:
    print("Usage: %s <pe_file_path>" % sys.argv[0]) 
    sys.exit(0)

pe_file_path = sys.argv[1]

with open(pe_file_path, "rb") as f:
    b = f.read()

if not b.startswith("MZ"):
    print("Not a PE file")
    sys.exit(0)

e_lfanew = struct.unpack_from("<I", b, 0x3C)[0]
vb = struct.pack("<HHHHH", 5, 0, 0, 0, 5) # encode versions
# patches MajorOperatingSystemVersion and MajorSubsystemVersion
b = b[0:e_lfanew + 0x40] + vb + b[e_lfanew + 0x4A:]
# write back to file
with open(pe_file_path, "wb") as f:
    f.write(b)

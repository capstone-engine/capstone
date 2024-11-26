# Copyright © 2024 Peace-Maker <peacemakerctf@gmail.com>
# SPDX-License-Identifier: BSD-3
# Compatibility header with pre v6 API
import capstone
import capstone.systemz
import capstone.systemz_const

setattr(capstone, "CS_ARCH_SYSZ", capstone.CS_ARCH_SYSTEMZ)
setattr(capstone, "__all__", getattr(capstone, "__all__") + ["CS_ARCH_SYSZ"])
compatibility_constants = [
    (name.replace("SYSTEMZ", "SYSZ"), getattr(capstone.systemz_const, name))
    for name in capstone.systemz_const.__dict__
    if name.startswith("SYSTEMZ")
]
globals().update(compatibility_constants)
for name, value in compatibility_constants:
    setattr(capstone.systemz, name, value)

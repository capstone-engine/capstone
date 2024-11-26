# Copyright © 2024 Peace-Maker <peacemakerctf@gmail.com>
# SPDX-License-Identifier: BSD-3
# Compatibility header with pre v6 API
import capstone
import capstone.aarch64_const

setattr(capstone, "CS_ARCH_ARM64", capstone.CS_ARCH_AARCH64)
setattr(capstone, "__all__", getattr(capstone, "__all__") + ["CS_ARCH_ARM64"])
globals().update(
    (name.replace("AARCH64", "ARM64"), getattr(capstone.aarch64_const, name))
    for name in capstone.aarch64_const.__dict__
    if name.startswith("AARCH64")
)
globals().update(
    (name.replace("AArch64CC", "ARM64_CC"), getattr(capstone.aarch64_const, name))
    for name in capstone.aarch64_const.__dict__
    if name.startswith("AArch64CC")
)

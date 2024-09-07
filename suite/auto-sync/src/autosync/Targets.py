# Copyright © 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

# Names of the target architectures as they are listed under llvm/lib/Target/
TARGETS_LLVM_NAMING = ["ARM", "PowerPC", "Alpha", "AArch64", "LoongArch", "SystemZ", "Mips"]

# Names of the target architecture as they are used in code and pretty much everywhere else.
ARCH_LLVM_NAMING = ["ARM", "PPC", "Alpha", "AArch64", "LoongArch", "SystemZ", "Mips"]

# Maps the target full name to the name used in code (and pretty much everywhere else).
TARGET_TO_IN_CODE_NAME = {
    "ARM": "ARM",
    "PowerPC": "PPC",
    "Alpha": "Alpha",
    "AArch64": "AArch64",
    "LoongArch": "LoongArch",
    "SystemZ": "SystemZ",
    "Mips": "Mips",
}

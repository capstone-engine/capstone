# Copyright © 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from autosync.PathVarHandler import PathVarHandler
import lit.formats

config.name = "Generate Capstone MC regression tests"
config.test_format = lit.formats.ShTest(True)

config.suffixes = [".txt", ".s"]

config.excludes = ["Inputs", "CMakeLists.txt", "README.txt", "LICENSE.txt"]

config.test_source_root = PathVarHandler().get_path("{LLVM_LIT_TEST_DIR}")

# Copyright © 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from autosync.Targets import TARGETS_LLVM_NAMING
from autosync.PathVarHandler import PathVarHandler
from pathlib import Path

import lit.llvm

lit.llvm.initialize(lit_config, config)

config.llvm_src_root = str(PathVarHandler().get_path("{LLVM_ROOT}").absolute())
config.root.targets = " ".join(TARGETS_LLVM_NAMING)

lit_cfg_dir = PathVarHandler().get_path("{LLVM_LIT_TEST_DIR}")
lit_config.load_config(config, lit_cfg_dir.joinpath("lit.cfg.py"))

#!/usr/bin/env python3
# Copyright © 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import argparse
import logging as log
import re
import sys
import subprocess as sp

from enum import Enum
from pathlib import Path
from lit import main

from autosync.Targets import TARGETS_LLVM_NAMING
from autosync.Helper import convert_loglevel, get_path
from autosync.PathVarHandler import PathVarHandler

# The CHECK prefix for tests.
ASM = r"(?P<asm_text>[^/@]+)"
ENC = r"(\[?(?P<enc_bytes>((0x[a-fA-F0-9]{1,2}[, ]{0,2}))+)[^, ]?\]?)"
match_patterns = {
    # The asm checking line for `MC/Disassembler/*` tests follows the pattern:
    # `# CHECK: <asm-text>`
    # Usually multiple 'CHECK' come before or after the encoding bytes.
    # Meaning: first comes a block of `# CHECK: ...` and afterwards for every `# CHECK: ...`
    # line the encoding bytes.
    # And wise versa, with the encoding bytes first and afterwards the asm text checks.
    # The matched asm text can be accessed from the group "asm_text"
    "asm_check": rf"\s+{ASM}\s*(#|//)\s+encoding:\s+{ENC}",
}


class Test:
    def __init__(self, encoding: str, asm_text: str):
        self.encoding: str = encoding
        self.asm_text: str = asm_text

    def __str__(self):
        self.encoding.replace(" ", ",")
        self.encoding = self.encoding.strip("[]")
        return f"{self.encoding} == {self.asm_text}"


class TestFile:
    def __init__(self, arch: str, filename: str, mattrs: list[str] | None):
        self.arch = arch
        self.filename = filename
        self.mattrs: list[str] = list() if not mattrs else mattrs
        self.tests: list[Test] = list()

    def has_tests(self) -> bool:
        return len(self.tests) != 0

    def get_cs_testfile_content(self) -> str:
        pass


class MCUpdater:
    def __init__(
        self,
        arch: str,
        mc_dir: Path,
        excluded: list[str] | None,
        included: list[str] | None,
    ):
        self.arch = arch
        self.mc_dir = mc_dir
        self.excluded = excluded if excluded else list()
        self.included = included if included else list()
        self.test_files: dict[str:TestFile] = dict()

    @staticmethod
    def get_mattr(line: str) -> str | None:
        match = re.search(match_patterns["run_line"], line)
        if not match or not match.group("mattr"):
            return None
        return match.group("mattr")

    def check_prerequisites(self, paths):
        for path in paths:
            if not path.exists() or not path.is_dir():
                raise ValueError(
                    f"'{path}' does not exits or is not a directory. Cannot generate tests from there."
                )
        llvm_lit = PathVarHandler().get_path("{LLVM_LIT_BIN}")
        if not llvm_lit.exists():
            raise ValueError(
                f"Could not find '{llvm_lit}'. Check {{LLVM_LIT_BIN}} in path_vars.json."
            )
        llvm_lit_cfg = PathVarHandler().get_path("{LLVM_LIT_CFG_DIR}")
        if not llvm_lit_cfg.exists():
            raise ValueError(
                f"Could not find '{llvm_lit_cfg}'. Check {{LLVM_LIT_CFG_DIR}} in path_vars.json."
            )

    def gen_all(self):
        log.info("Check prerequisites")
        disas_tests = self.mc_dir.joinpath(f"Disassembler/{self.arch}")
        assembly_tests = self.mc_dir.joinpath(f"{self.arch}")
        test_paths = [disas_tests, assembly_tests]
        self.check_prerequisites(test_paths)
        log.info("Generate MC regression tests")
        llvm_mc_cmds = self.run_llvm_lit(test_paths)

        # self.write_to_build_dir()

    def write_to_build_dir(self):
        for filename, test in self.test_files.items():
            if not test.has_tests():
                continue
            with open(
                get_path("{MCUPDATER_OUT_DIR}").joinpath(f"{filename}.cs"), "w+"
            ) as f:
                f.write(test.get_cs_testfile_content())
            log.debug(f"Write {filename}")

    def run_llvm_lit(self, paths: list[Path]) -> list[str]:
        """
        Calls llvm-lit with the given paths to the tests.
        It saves the output of llvm-mc to each file in a temp directory.
        """
        llvm_lit = str(PathVarHandler().get_path("{LLVM_LIT_BIN}").absolute())
        lit_cfg_dir = PathVarHandler().get_path("{LLVM_LIT_CFG_DIR}")
        llvm_lit_cfg = str(lit_cfg_dir.absolute())
        args = [llvm_lit, "-v", "-a", llvm_lit_cfg]
        for i, p in enumerate(paths):
            slink = lit_cfg_dir.joinpath(f"test_dir_{i}")
            try:
                slink.symlink_to(p, target_is_directory=True)
            except FileExistsError:
                pass

        cmds = sp.run(args, capture_output=True)
        if cmds.stderr:
            log.error(f"llvm-lit failed with {cmds.stderr}")
        return self.extract_llvm_mc_cmds(cmds.stdout)

    def extract_llvm_mc_cmds(self, cmds: str) -> list[str]:
        pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Test file updater",
        description="Synchronizes test files with LLVM",
    )
    parser.add_argument(
        "-d",
        dest="mc_dir",
        help=f"Path to the LLVM MC test files. Default: {get_path('{LLVM_MC_TEST_DIR}')}",
        default=get_path("{LLVM_MC_TEST_DIR}"),
        type=Path,
    )
    parser.add_argument(
        "-a",
        dest="arch",
        help="Name of architecture to update.",
        choices=TARGETS_LLVM_NAMING,
        required=True,
    )
    parser.add_argument(
        "-e",
        dest="excluded_files",
        metavar="filename",
        nargs="+",
        help="File names to exclude from update (can be a regex pattern).",
    )
    parser.add_argument(
        "-i",
        dest="included_files",
        metavar="filename",
        nargs="+",
        help="Specific list of file names to update (can be a regex pattern).",
    )
    parser.add_argument(
        "-v",
        dest="verbosity",
        help="Verbosity of the log messages.",
        choices=["debug", "info", "warning", "fatal"],
        default="info",
    )
    arguments = parser.parse_args()
    return arguments


if __name__ == "__main__":
    args = parse_args()
    log.basicConfig(
        level=convert_loglevel(args.verbosity),
        stream=sys.stdout,
        format="%(levelname)-5s - %(message)s",
        force=True,
    )

    MCUpdater(
        args.arch, args.mc_dir, args.excluded_files, args.included_files
    ).gen_all()

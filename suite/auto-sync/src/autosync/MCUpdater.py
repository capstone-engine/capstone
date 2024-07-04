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


class LLVM_MC_Command:
    def __init__(self, cmd_line: str):
        self.cmd: str = ""
        self.opts: str = ""
        self.file: Path | None = None

        self.cmd, self.opts, self.file = self.parse_llvm_mc_line(cmd_line)
        if not (self.cmd and self.opts and self.file):
            raise ValueError(f"Could not parse llvm-mc command: {cmd_line}")

    def parse_llvm_mc_line(self, line: str) -> tuple[str, str, Path]:
        test_file_base_dir = str(
            PathVarHandler().get_path("{LLVM_LIT_CFG_DIR}").absolute()
        )
        file = re.findall(rf"{test_file_base_dir}[^\s]+", line)
        if not file:
            raise ValueError(f"llvm-mc command doesn't contain a file: {line}")
        test_file = file[0]
        cmd = re.sub(rf"{test_file}", "", line).strip()
        arch = re.finditer(r"(triple|arch)[=\s]([^\s]+)", cmd)
        mattr = re.finditer(r"(mattr|mcpu)[=\s]([^\s]+)", cmd)
        opts = ",".join([m.group(2) for m in arch]) if arch else ""
        opts += ",".join([m.group(2) for m in mattr]) if mattr else ""
        return cmd, opts, Path(test_file)

    def exec(self) -> str:
        result = sp.run(self.cmd, input=str(self.file.absolute()), capture_output=True)
        if result.stderr:
            raise ValueError(f"llvm-mc failed with: '{result.stderr}'")
        result.stdout

    def __str__(self) -> str:
        return f"{self.cmd} < {str(self.file.absolute())}"


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
        for cmd in llvm_mc_cmds:
            print(cmd)

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

    def run_llvm_lit(self, paths: list[Path]) -> list[LLVM_MC_Command]:
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

        log.debug(f"Run lit: {args}")
        cmds = sp.run(args, capture_output=True)
        if cmds.stderr:
            raise ValueError(f"llvm-lit failed with {cmds.stderr}")
        return self.extract_llvm_mc_cmds(cmds.stdout.decode("utf8"))

    def extract_llvm_mc_cmds(self, cmds: str) -> list[LLVM_MC_Command]:
        # Get only the RUN lines which have a show-encoding set.
        matches = filter(
            lambda l: l if re.search(r"^RUN.+show-encoding[^|]+", l) else None,
            cmds.splitlines(),
        )
        # Don't add tests which are allowed to fail
        matches = filter(
            lambda m: None if re.search(r"not\s+llvm-mc", m) else m, matches
        )
        # Remove 'RUN: at ...' prefix
        matches = map(lambda m: re.sub(r"^RUN: at line \d+: ", "", m), matches)
        # Remove redirections
        matches = map(lambda m: re.sub(r"\d>&\d", "", m), matches)
        # Remove explicit writing to stdin
        matches = map(lambda m: re.sub(r"-o\s?-", "", m), matches)
        # Remove redirection of stderr to a file
        matches = map(lambda m: re.sub(r"2>\s?[^\s]+", "", m), matches)
        # Remove pipeing to FileCheck
        matches = map(lambda m: re.sub(r"\|\s*FileCheck\s+.+", "", m), matches)
        # Remove input stream
        matches = map(lambda m: re.sub(r"\s+<", "", m), matches)

        all_cmds = list()
        for match in matches:
            if self.included and not any(
                re.search(x, match) is not None for x in self.included
            ):
                continue
            if any(re.search(x, match) is not None for x in self.excluded):
                continue

            all_cmds.append(LLVM_MC_Command(match))
        return all_cmds


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

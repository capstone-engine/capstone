#!/usr/bin/env python3

# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import argparse

import logging as log
import os
import shutil
import subprocess
import sys
from enum import StrEnum
from pathlib import Path

from autosync.cpptranslator.Configurator import Configurator
from autosync.cpptranslator.CppTranslator import Translator
from autosync.HeaderPatcher import HeaderPatcher
from autosync.Helper import check_py_version, convert_loglevel, fail_exit, get_path

from autosync.IncGenerator import IncGenerator


class USteps(StrEnum):
    INC_GEN = "IncGen"
    TRANS = "Translate"
    DIFF = "Diff"
    ALL = "All"


class ASUpdater:
    """
    The auto-sync updater.
    """

    def __init__(
        self,
        arch: str,
        write: bool,
        steps: list[USteps],
        inc_list: list,
        no_clean: bool,
        refactor: bool,
        differ_no_auto_apply: bool,
        wait_for_user: bool = True,
    ) -> None:
        self.arch = arch
        self.write = write
        self.no_clean_build = no_clean
        self.inc_list = inc_list
        self.wait_for_user = wait_for_user
        if USteps.ALL in steps:
            self.steps = [USteps.INC_GEN, USteps.TRANS, USteps.DIFF]
        else:
            self.steps = steps
        self.refactor = refactor
        self.differ_no_auto_apply = differ_no_auto_apply
        self.arch_dir = get_path("{CS_ARCH_MODULE_DIR}").joinpath(self.arch)
        if not self.no_clean_build:
            self.clean_build_dir()
        self.inc_generator = IncGenerator(
            self.arch,
            self.inc_list,
        )

    def clean_build_dir(self) -> None:
        log.info("Clean build directory")
        path: Path
        for path in get_path("{BUILD_DIR}").iterdir():
            log.debug(f"Delete {path}")
            if path.is_dir():
                shutil.rmtree(path)
            else:
                os.remove(path)

    def patch_main_header(self) -> list:
        """
        Patches the main header of the arch with the .inc files.
        It returns a list of files it has patched into the main header.
        """
        if not self.write:
            return []
        main_header = get_path("{CS_INCLUDE_DIR}").joinpath(f"{self.arch.lower()}.h")
        # Just try every inc file
        patched = []
        for file in get_path("{C_INC_OUT_DIR}").iterdir():
            patcher = HeaderPatcher(main_header, file)
            if patcher.patch_header():
                # Save the path. This file should not be moved.
                patched.append(file)
        return patched

    def copy_files(self, path: Path, dest: Path) -> None:
        """
        Copies files from path to dest.
        If path is a directory it copies all files in it.
        If it is a file, it only copies it.
        """
        if not self.write:
            return
        if not dest.is_dir():
            fail_exit(f"{dest} is not a directory.")

        if path.is_file():
            log.debug(f"Copy {path} to {dest}")
            shutil.copy(path, dest)
            return

        for file in path.iterdir():
            log.debug(f"Copy {path} to {dest}")
            shutil.copy(file, dest)

    def check_tree_sitter(self) -> None:
        ts_dir = get_path("{VENDOR_DIR}").joinpath("tree-sitter-cpp")
        if not ts_dir.exists():
            log.info("tree-sitter was not fetched. Cloning it now...")
            subprocess.run(
                ["git", "submodule", "update", "--init", "--recursive"], check=True
            )

    def translate(self) -> None:
        self.check_tree_sitter()
        translator_config = get_path("{CPP_TRANSLATOR_CONFIG}")
        configurator = Configurator(self.arch, translator_config)
        translator = Translator(configurator, self.wait_for_user)
        translator.translate()
        translator.remark_manual_files()

    def diff(self) -> None:
        translator_config = get_path("{CPP_TRANSLATOR_CONFIG}")
        configurator = Configurator(self.arch, translator_config)
        from autosync.cpptranslator.Differ import Differ

        differ = Differ(configurator, self.differ_no_auto_apply)
        differ.diff()

    def update(self) -> None:
        if USteps.INC_GEN in self.steps:
            self.inc_generator.generate()
            # Runtime for large files is huge
            # Use helper clang-format
            # self.run_clang_format(self.conf["build_dir_path"].joinpath(C_INC_OUT_DIR))
            patched = self.patch_main_header()
            for file in get_path("{C_INC_OUT_DIR}").iterdir():
                if file in patched:
                    continue
                self.copy_files(file, self.arch_dir)
        if USteps.TRANS in self.steps:
            self.translate()
        if USteps.DIFF in self.steps:
            self.diff()
        # Write files
        exit(0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Auto-Sync-Updater",
        description="Capstones architecture module updater.",
    )
    parser.add_argument(
        "-a",
        dest="arch",
        help="Name of target architecture.",
        choices=["ARM", "PPC", "AArch64", "Alpha"],
        required=True,
    )
    parser.add_argument(
        "-d",
        dest="no_clean",
        help="Don't clean build dir before updating.",
        action="store_true",
    )
    parser.add_argument(
        "-w",
        dest="write",
        help="Write generated/translated files to arch/<ARCH>/",
        action="store_true",
    )
    parser.add_argument(
        "-v",
        dest="verbosity",
        help="Verbosity of the log messages.",
        choices=["debug", "info", "warning", "fatal"],
        default="info",
    )
    parser.add_argument(
        "-e",
        dest="no_auto_apply",
        help="Differ: Do not apply saved diff resolutions. Ask for every diff again.",
        action="store_true",
    )
    parser.add_argument(
        "-s",
        dest="steps",
        help="List of update steps to perform. If omitted, it performs all update steps.",
        choices=[
            "All",
            "IncGen",
            "Translate",
            "Diff",
        ],
        nargs="+",
        type=USteps,
        default=["All"],
    )
    parser.add_argument(
        "--inc-list",
        dest="inc_list",
        help="Only generate the following inc files.",
        choices=[
            "All",
            "Disassembler",
            "AsmWriter",
            "RegisterInfo",
            "InstrInfo",
            "SubtargetInfo",
            "Mapping",
            "SystemOperand",
        ],
        nargs="+",
        type=str,
        default=["All"],
    )
    parser.add_argument(
        "--refactor",
        dest="refactor",
        help="Sets change update behavior to ease refactoring and new implementations.",
        action="store_true",
    )
    parser.add_argument(
        "--ci",
        dest="wait_for_user",
        help="The translator will not wait for user input when printing important logs.",
        action="store_false",
    )
    arguments = parser.parse_args()
    return arguments


if __name__ == "__main__":
    check_py_version()

    args = parse_args()
    log.basicConfig(
        level=convert_loglevel(args.verbosity),
        stream=sys.stdout,
        format="%(levelname)-5s - %(message)s",
    )

    Updater = ASUpdater(
        args.arch,
        args.write,
        args.steps,
        args.inc_list,
        args.no_clean,
        args.refactor,
        args.no_auto_apply,
        args.wait_for_user,
    )
    Updater.update()

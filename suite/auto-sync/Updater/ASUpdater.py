#!/usr/bin/env python3

import argparse
import json
import shutil
import subprocess
import sys

import logging as log

# from CppTranslator import CppTranslator
from IncGenerator import IncGenerator
from Helper import get_path, convert_loglevel, check_py_version, fail_exit
from PatchMainHeader import HeaderPatcher
from pathlib import Path


class ASUpdater:
    """
    The auto-sync updater.
    """

    def __init__(self, arch: str, write: bool, inc_only: bool, inc_list: list, no_clean: bool) -> None:
        self.arch = arch
        self.write = write
        self.no_clean_build = no_clean
        self.inc_list = inc_list
        self.inc_only = inc_only
        self.refactor = refactor
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
                shutil.remove(path)

    def patch_main_header(self) -> list:
        """
        Patches the main header of the arch with the .inc files.
        It returns a list of files it has patched into the main header.
        """
        main_header = get_path("{CS_INCLUDE_DIR}").joinpath(f"{self.arch.lower()}.h")
        # Just try every inc file
        patched = []
        for file in get_path("{C_INC_OUT_DIR}").iterdir():
            patcher = HeaderPatcher(main_header, file)
            if patcher.patch_header():
                # Save the path. This file should not be moved.
                patched.append(file)
        return patched

    def run_clang_format(self, path: Path) -> None:
        """
        Runs clang-format on path (dir and file).
        """

        log.info(f"Format files in {path} (might take a while)")
        if path.is_file():
            log.debug(f"Format {path}")
            subprocess.run(
                ["clang-format-18", "-i", f"--style=file:{get_path('{CS_ROOT}')}/.clang-format", str(path)], check=True
            )
            return

        for file in path.iterdir():
            log.debug(f"Format {file}")
            subprocess.run(
                ["clang-format-18", "-i", f"--style=file:{get_path('{CS_ROOT}')}/.clang-format", str(file)], check=True
            )

    def copy_files(self, path: Path, dest: Path) -> None:
        """
        Copies files from path to dest.
        If path is a directory it copies all files in it.
        If it is a file, it only copies it.
        """
        if not dest.is_dir():
            fail_exit(f"{dest} is not a directory.")

        if path.is_file():
            log.debug(f"Copy {path} to {dest}")
            shutil.copy(path, dest)
            return

        for file in path.iterdir():
            log.debug(f"Copy {path} to {dest}")
            shutil.copy(path, dest)

    def update(self) -> None:
        self.inc_generator.generate()
        # Runtime for large files is huge
        # self.run_clang_format(self.conf["build_dir_path"].joinpath(C_INC_OUT_DIR))
        if self.write:
            patched = self.patch_main_header()
            for file in get_path("{C_INC_OUT_DIR}").iterdir():
                if file in patched:
                    continue
                self.copy_files(file, self.arch_dir)

        # Move them
        if self.inc_only:
            exit(0)
        fail_exit("Full update procedure not yet implemented.")
        # Move them


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Auto-Sync-Updater",
        description="Capstones architecture module updater.",
    )
    parser.add_argument(
        "-a", dest="arch", help="Name of target architecture.", choices=["ARM", "PPC", "AArch64"], required=True
    )
    parser.add_argument("-d", dest="no_clean", help="Don't clean build dir before updating.", action="store_true")
    parser.add_argument(
        "-w", dest="write", help="Write generated/translated files to arch/<ARCH>/", action="store_true"
    )
    parser.add_argument(
        "-v",
        dest="verbosity",
        help="Verbosity of the log messages.",
        choices=["debug", "info", "warning", "fatal"],
        default="info",
    )
    parser.add_argument("--inc-only", dest="inc_only", help="Only generate the inc files.", action="store_true")
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

    Updater = ASUpdater(args.arch, args.write, args.inc_only, args.inc_list, args.no_clean)
    Updater.update()

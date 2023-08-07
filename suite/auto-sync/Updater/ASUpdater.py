#!/usr/bin/env python3

import argparse
import json
import shutil
import subprocess
import sys

import logging as log

from IncGenerator import IncGenerator, C_INC_OUT_DIR
from Helper import get_path, convert_loglevel, check_py_version, fail_exit
from PatchMainHeader import HeaderPatcher
from pathlib import Path

CONFIG_FILE_NAME = "config.json"
CONFIG_DEFAULT_CONTENT = """{
    "llvm_capstone_path": "{AUTO_SYNC_ROOT}/llvm-capstone/",
    "vendor_path": "{AUTO_SYNC_ROOT}/vendor/",
    "build_dir_path": "{AUTO_SYNC_ROOT}/build/",
    "patches_dir_path": "{AUTO_SYNC_ROOT}/inc_patches/",
    "cs_include_dir": "{CS_ROOT}/include/capstone/",
    "cs_arch_module_dir": "{CS_ROOT}/arch/"
}
"""


class ASUpdater:
    """
    The auto-sync updater.
    """

    def __init__(self, arch: str, write: bool, inc_only: bool, inc_list: list, clean: bool) -> None:
        self.arch = arch
        self.write = write
        self.clean_build = clean
        self.inc_list = inc_list
        self.inc_only = inc_only
        self.conf = self.get_config()
        self.arch_dir = self.conf["cs_arch_module_dir"].joinpath(self.arch)
        if self.clean_build:
            self.clean_build_dir()
        self.check_paths()
        self.inc_generator = IncGenerator(
            self.arch,
            self.inc_list,
            self.conf["llvm_capstone_path"],
            self.conf["patches_dir_path"],
            self.conf["build_dir_path"],
        )

    def clean_build_dir(self) -> None:
        log.info("Clean build directory")
        path: Path
        for path in self.conf["build_dir_path"].iterdir():
            log.debug(f"Delete {path}")
            if path.is_dir():
                shutil.rmtree(path)
            else:
                shutil.remove(path)

    @staticmethod
    def get_config() -> dict:
        if not Path.exists(Path(CONFIG_FILE_NAME)):
            log.info(f"{CONFIG_FILE_NAME} not found. Creating new one.")
            with open(CONFIG_FILE_NAME, "x") as f:
                f.write(CONFIG_DEFAULT_CONTENT)
        with open(CONFIG_FILE_NAME) as f:
            raw_conf = json.load(f)
        conf = dict()
        for k, v in raw_conf.items():
            conf[k] = get_path(v)
        return conf

    def check_paths(self) -> None:
        if not self.conf["llvm_capstone_path"].exists():
            fail_exit(f"Could not find {self.conf['llvm_capstone_path'].name}")
        if not self.conf["build_dir_path"].exists():
            fail_exit(f"Could not find {self.conf['build_dir_path'].name}")
        if not self.conf["vendor_path"].exists():
            fail_exit(f"Could not find {self.conf['vendor_path'].name}")
        if not self.conf["patches_dir_path"].exists():
            fail_exit(f"Could not find {self.conf['patches_dir_path'].name}")
        if not self.conf["cs_include_dir"].exists():
            fail_exit(f"Could not find {self.conf['cs_include_dir'].name}")
        if not self.conf["cs_arch_module_dir"].exists():
            fail_exit(f"Could not find {self.conf['cs_arch_module_dir'].name}")

    def patch_main_header(self) -> list:
        """
        Patches the main header of the arch with the .inc files.
        It returns a list of files it has patched into the main header.
        """
        main_header = self.conf["cs_include_dir"].joinpath(f"{self.arch.lower()}.h")
        # Just try every inc file
        patched = []
        for file in self.conf["build_dir_path"].joinpath(C_INC_OUT_DIR).iterdir():
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
            for file in self.conf["build_dir_path"].joinpath(C_INC_OUT_DIR).iterdir():
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
    parser.add_argument("-c", dest="clean", help="Clean build dir before updating.", action="store_true")
    parser.add_argument("-w", dest="write", help="Copy generated files to arch/<ARCH>/", action="store_true")
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

    Updater = ASUpdater(args.arch, args.write, args.inc_only, args.inc_list, args.clean)
    Updater.update()

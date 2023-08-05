#!/usr/bin/env python3

import argparse
import json
import sys

import logging as log

from IncGenerator import IncGenerator
from Helper import get_path, convert_loglevel, check_py_version, fail_exit
from pathlib import Path

CONFIG_FILE_NAME = "config.json"
CONFIG_DEFAULT_CONTENT = """
    {
        "llvm_capstone_path": "{AUTO_SYNC_ROOT}/llvm-capstone/",
        "vendor_path": "{AUTO_SYNC_ROOT}/vendor/",
        "build_dir_path": "{AUTO_SYNC_ROOT}/build/"
    }
    """


class ASUpdater:
    """
    The auto-sync updater.
    """

    def __init__(self, arch: str, write: bool, inc_only: bool, inc_list: list) -> None:
        self.arch = arch
        self.write = write
        self.inc_list = inc_list
        self.inc_only = inc_only
        self.conf = self.get_config()
        self.check_paths()
        self.inc_generator = IncGenerator(
            self.arch, self.inc_list, self.conf["llvm_capstone_path"], self.conf["build_dir_path"]
        )

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

    def update(self) -> None:
        if self.inc_only:
            self.inc_generator.gen_incs()
            # Move them
            exit(0)
        fail_exit("Full update procedure not yet implemented.")
        self.inc_generator.gen_incs()
        # Move them


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Auto-Sync-Updater",
        description="Capstones architecture module updater.",
    )
    parser.add_argument(
        "-a", dest="arch", help="Name of target architecture.", choices=["ARM", "PPC", "AArch64"], required=True
    )
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

    Updater = ASUpdater(args.arch, args.write, args.inc_only, args.inc_list)
    Updater.update()

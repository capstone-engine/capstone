#!/usr/bin/env python3

import argparse
import json
import sys

import logging as log

from Helper import get_path, convert_loglevel, check_py_version
from pathlib import Path

CONFIG_FILE_NAME = "config.json"
CONFIG_DEFAULT_CONTENT = """
    {
        "llvm_capstone_path" = "{AUTO_SYNC_ROOT}/llvm-capstone/",
        "vendor_path" = "{AUTO_SYNC_ROOT}/vendor/",
        "build_dir_path" = "{AUTO_SYNC_ROOT}/build/"
    }
    """


class ASUpdater:
    """
    The auto-sync updater.
    """

    def __init__(self, write: bool, inc_only: bool) -> None:
        self.write = write
        self.inc_only = inc_only
        self.conf = self.get_config()

    @staticmethod
    def get_config(self) -> dict:
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

    def update(self) -> None:
        if self.inc_only:
            pass
        log.warn("Not yet implemented.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Auto-Sync-Updater",
        description="Capstones architecture module updater.",
    )
    parser.add_argument(
        "-a", dest="arch", help="Name of target architecture.", choices=["ARM", "PPC", "AArch64"], required=True
    )
    parser.add_argument("-w", dest="write", help="Copy generated files to arch/<ARCH>/", default=False, type=bool)
    parser.add_argument(
        "-v",
        dest="verbosity",
        help="Verbosity of the log messages.",
        choices=["debug", "info", "warning", "fatal"],
        default="info",
    )
    parser.add_argument("--inc-only", dest="inc_only", help="Only generate the inc files.", default=False, type=bool)
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

    Updater = ASUpdater(args.write, args.inc_only)

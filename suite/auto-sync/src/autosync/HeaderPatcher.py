#!/usr/bin/env python3

# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import argparse
import logging as log
import re

from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="PatchHeaders",
        description="Patches generated enums into the main arch header file.",
    )
    parser.add_argument(
        "--header", dest="header", help="Path header file.", type=Path, required=True
    )
    parser.add_argument(
        "--inc", dest="inc", help="Path inc file.", type=Path, required=True
    )
    arguments = parser.parse_args()
    return arguments


def error_exit(msg: str) -> None:
    log.fatal(f"{msg}")
    exit(1)


class HeaderPatcher:
    def __init__(self, header: Path, inc: Path, write_file: bool = True) -> None:
        self.header = header
        self.inc = inc
        self.inc_content: str = ""
        self.write_file = write_file
        # Gets set to the patched file content if writing to the file is disabled.
        self.patched_header_content: str = ""

    def patch_header(self) -> bool:
        if not (self.header.exists() or self.header.is_file()):
            error_exit(f"self.Header file {self.header.name} does not exist.")

        if not (self.inc.exists() or self.inc.is_file()):
            error_exit(f".self.inc file {self.inc.name} does not exist.")

        with open(self.header) as f:
            header_content = f.read()

        if self.inc.name not in header_content:
            log.debug(f"{self.inc.name} has no include comments in {self.header.name}")
            return False

        with open(self.inc) as f:
            self.inc_content = f.read()

        to_write: dict[str:str] = {}
        enum_vals_id = ""
        for line in self.inc_content.splitlines():
            # No comments and empty lines
            if "/*" == line[:2] or not line:
                continue

            if "#ifdef" in line:
                enum_vals_id = line[7:].strip("\n")
                to_write[enum_vals_id] = ""
            elif "#endif" in line and not enum_vals_id == "NOTGIVEN":
                enum_vals_id = ""
            elif "#undef" in line:
                continue
            else:
                if not enum_vals_id:
                    enum_vals_id = "NOTGIVEN"
                    to_write[enum_vals_id] = line + "\n"
                    continue
                to_write[enum_vals_id] += re.sub(r"^(\s+)?", "\t", line) + "\n"
        for ev_id in to_write.keys():
            header_enum_id = f":{ev_id}" if ev_id != "NOTGIVEN" else ""
            regex = (
                rf"\s*// generated content <{self.inc.name}{header_enum_id}> begin.*(\n)"
                rf"(.*\n)*"
                rf"\s*// generated content <{self.inc.name}{header_enum_id}> end.*(\n)"
            )
            if not re.search(regex, header_content):
                error_exit(f"Could not locate include comments for {self.inc.name}")

            new_content = (
                f"\n\t// generated content <{self.inc.name}{header_enum_id}> begin\n"
                + "\t// clang-format off\n\n"
                + to_write[ev_id]
                + "\n\t// clang-format on\n"
                + f"\t// generated content <{self.inc.name}{header_enum_id}> end\n"
            )

            header_content = re.sub(regex, new_content, header_content)
        if self.write_file:
            with open(self.header, "w") as f:
                f.write(header_content)
        else:
            self.patched_header_content = header_content
        log.info(f"Patched {self.inc.name} into {self.header.name}")
        return True


if __name__ == "__main__":
    args = parse_args()
    patcher = HeaderPatcher(args.header, args.inc)
    patcher.patch_header()

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
    parser.add_argument("--header", dest="header", help="Path header file.", type=Path)
    parser.add_argument("--inc", dest="inc", help="Path inc file.", type=Path)
    parser.add_argument(
        "--aarch64", dest="aarch64", help="aarch64.h header file location", type=Path
    )
    parser.add_argument(
        "--arm64", dest="arm64", help="arm64.h header file location", type=Path
    )
    parser.add_argument(
        "-c", dest="compat", help="Generate compatibility header", action="store_true"
    )
    parser.add_argument(
        "-p", dest="patch", help="Patch inc file into header", action="store_true"
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
            error_exit(f"self.header file {self.header.name} does not exist.")

        if not (self.inc.exists() or self.inc.is_file()):
            error_exit(f"self.inc file {self.inc.name} does not exist.")

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
                line = re.sub(r"^(\s+)?", "\t", line)
                if not enum_vals_id:
                    enum_vals_id = "NOTGIVEN"
                    to_write[enum_vals_id] = line + "\n"
                    continue
                to_write[enum_vals_id] += line + "\n"
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

    @staticmethod
    def file_in_main_header(header: Path, filename: str) -> bool:
        with open(header) as f:
            header_content = f.read()
        return filename in header_content


class CompatHeaderBuilder:

    def __init__(self, aarch64_h: Path, arm64_h: Path):
        self.aarch64_h = aarch64_h
        self.arm64_h = arm64_h

    def replace_typedef_struct(self, aarch64_lines: list[str]) -> list[str]:
        output = list()
        typedef = ""
        for line in aarch64_lines:
            if typedef:
                if not re.search(r"^}\s[\w_]+;", line):
                    # Skip struct content
                    continue
                type_name = re.findall(r"[\w_]+", line)[0]
                output.append(
                    f"typedef {type_name} {re.sub('aarch64','arm64', type_name)};\n"
                )
                typedef = ""
                continue

            if re.search(f"^typedef\s+(struct|union)", line):
                typedef = line
                continue
            output.append(line)
        return output

    def replace_typedef_enum(self, aarch64_lines: list[str]) -> list[str]:
        output = list()
        typedef = ""
        for line in aarch64_lines:
            if typedef:
                if not re.search(r"^}\s[\w_]+;", line):
                    # Replace name
                    if "AArch64" not in line and "AARCH64" not in line:
                        output.append(line)
                        continue
                    found = re.findall(r"(AArch64|AARCH64)([\w_]+)", line)
                    entry_name: str = "".join(found[0])
                    arm64_name = entry_name.replace("AArch64", "ARM64").replace(
                        "AARCH64", "ARM64"
                    )
                    patched_line = re.sub(
                        r"(AArch64|AARCH64).+", f"{arm64_name} = {entry_name},", line
                    )
                    output.append(patched_line)
                    continue
                # We still have LLVM and CS naming conventions mixed
                p = re.sub(r"aarch64", "arm64", line)
                p = re.sub(r"(AArch64|AARCH64)", "ARM64", p)
                output.append(p)
                typedef = ""
                continue

            if re.search(f"^typedef\s+enum", line):
                typedef = line
                output.append("typedef enum {\n")
                continue
            output.append(line)
        return output

    def remove_comments(self, aarch64_lines: list[str]) -> list[str]:
        output = list()
        for line in aarch64_lines:
            if re.search(r"^\s*//", line) and "// SPDX" not in line:
                continue
            output.append(line)
        return output

    def replace_aarch64(self, aarch64_lines: list[str]) -> list[str]:
        output = list()
        in_typedef = False
        for line in aarch64_lines:
            if in_typedef:
                if re.search(r"^}\s[\w_]+;", line):
                    in_typedef = False
                output.append(line)
                continue

            if re.search(f"^typedef", line):
                in_typedef = True
                output.append(line)
                continue
            output.append(re.sub(r"(AArch64|AARCH64)", "ARM64", line))
        return output

    def replace_include_guards(self, aarch64_lines: list[str]) -> list[str]:
        output = list()
        for line in aarch64_lines:
            if not re.search(r"^#(ifndef|define)", line):
                output.append(line)
                continue
            output.append(re.sub(r"AARCH64", "ARM64", line))
        return output

    def inject_aarch64_header(self, aarch64_lines: list[str]) -> list[str]:
        output = list()
        header_inserted = False
        for line in aarch64_lines:
            if re.search(r"^#include", line):
                if not header_inserted:
                    output.append("#include <capstone/aarch64.h>\n")
                    header_inserted = True
            output.append(line)
        return output

    def generate_aarch64_compat_header(self) -> bool:
        """
        Translates the aarch64.h header into the arm64.h header and renames all aarch64 occurrences.
        It does simple regex matching and replacing.
        """
        log.info("Generate compatibility header")
        with open(self.aarch64_h) as f:
            aarch64 = f.readlines()

        patched = self.replace_typedef_struct(aarch64)
        patched = self.replace_typedef_enum(patched)
        patched = self.remove_comments(patched)
        patched = self.replace_aarch64(patched)
        patched = self.replace_include_guards(patched)
        patched = self.inject_aarch64_header(patched)

        with open(self.arm64_h, "w+") as f:
            f.writelines(patched)


if __name__ == "__main__":
    args = parse_args()
    if (not args.patch and not args.compat) or (args.patch and args.compat):
        print("You need to specify either -c or -p")
        exit(1)
    if args.compat and not (args.aarch64 and args.arm64):
        print(
            "Generating the arm64 compatibility header requires --arm64 and --aarch64"
        )
        exit(1)
    if args.patch and not (args.inc and args.header):
        print("Patching headers requires --inc and --header")
        exit(1)

    if args.patch:
        patcher = HeaderPatcher(args.header, args.inc)
        patcher.patch_header()
        exit(0)

    builder = CompatHeaderBuilder(args.aarch64, args.arm64)
    builder.generate_aarch64_compat_header()

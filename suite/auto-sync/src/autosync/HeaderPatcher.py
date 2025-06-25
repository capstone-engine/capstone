#!/usr/bin/env python3

# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import argparse
import logging as log
import re
import subprocess as sp

from pathlib import Path

AARCH64_CC_MACROS = [
    "\n",
    "#define arm64_cc AArch64CC_CondCode\n",
    "#define ARM64_CC_EQ AArch64CC_EQ\n",
    "#define ARM64_CC_NE AArch64CC_NE\n",
    "#define ARM64_CC_HS AArch64CC_HS\n",
    "#define ARM64_CC_LO AArch64CC_LO\n",
    "#define ARM64_CC_MI AArch64CC_MI\n",
    "#define ARM64_CC_PL AArch64CC_PL\n",
    "#define ARM64_CC_VS AArch64CC_VS\n",
    "#define ARM64_CC_VC AArch64CC_VC\n",
    "#define ARM64_CC_HI AArch64CC_HI\n",
    "#define ARM64_CC_LS AArch64CC_LS\n",
    "#define ARM64_CC_GE AArch64CC_GE\n",
    "#define ARM64_CC_LT AArch64CC_LT\n",
    "#define ARM64_CC_GT AArch64CC_GT\n",
    "#define ARM64_CC_LE AArch64CC_LE\n",
    "#define ARM64_CC_AL AArch64CC_AL\n",
    "#define ARM64_CC_NV AArch64CC_NV\n",
    "#define ARM64_CC_INVALID AArch64CC_Invalid\n",
    "#define ARM64_VAS_INVALID AARCH64LAYOUT_INVALID\n",
    "#define ARM64_VAS_16B AARCH64LAYOUT_VL_16B\n",
    "#define ARM64_VAS_8B AARCH64LAYOUT_VL_8B\n",
    "#define ARM64_VAS_4B AARCH64LAYOUT_VL_4B\n",
    "#define ARM64_VAS_1B AARCH64LAYOUT_VL_1B\n",
    "#define ARM64_VAS_8H AARCH64LAYOUT_VL_8H\n",
    "#define ARM64_VAS_4H AARCH64LAYOUT_VL_4H\n",
    "#define ARM64_VAS_2H AARCH64LAYOUT_VL_2H\n",
    "#define ARM64_VAS_1H AARCH64LAYOUT_VL_1H\n",
    "#define ARM64_VAS_4S AARCH64LAYOUT_VL_4S\n",
    "#define ARM64_VAS_2S AARCH64LAYOUT_VL_2S\n",
    "#define ARM64_VAS_1S AARCH64LAYOUT_VL_1S\n",
    "#define ARM64_VAS_2D AARCH64LAYOUT_VL_2D\n",
    "#define ARM64_VAS_1D AARCH64LAYOUT_VL_1D\n",
    "#define ARM64_VAS_1Q AARCH64LAYOUT_VL_1Q\n",
    "#define arm64_vas AArch64Layout_VectorLayout\n",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="PatchHeaders",
        description="Patches generated enums into the main arch header file.",
    )
    parser.add_argument("--header", dest="header", help="Path header file.", type=Path)
    parser.add_argument("--inc", dest="inc", help="Path inc file.", type=Path)
    parser.add_argument(
        "--v6", dest="v6", help="aarch64.h/systemz.h header file location", type=Path
    )
    parser.add_argument(
        "--v5", dest="v5", help="arm64.h/systemz_v5.h header file location", type=Path
    )
    parser.add_argument(
        "-c", dest="compat", help="Generate compatibility header", action="store_true"
    )
    parser.add_argument(
        "-p", dest="patch", help="Patch inc file into header", action="store_true"
    )
    parser.add_argument(
        "-C",
        dest="clang_format",
        help=".clang-format file to use for formatting",
        type=Path,
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
    def __init__(self, v6: Path, v5: Path, arch: str, clang_format: Path | None = None):
        self.v6 = v6
        self.v5 = v5
        self.clang_format = clang_format
        match arch:
            case "aarch64":
                self.v6_lower = "aarch64"
                self.v6_upper = "AARCH64"
                self.v6_camel = "AArch64"
                self.v5_lower = "arm64"
                self.v5_upper = "ARM64"
            case "systemz":
                self.v6_lower = "systemz"
                self.v6_upper = "SYSTEMZ"
                self.v6_camel = "SystemZ"
                self.v5_lower = "sysz"
                self.v5_upper = "SYSZ"
            case _:
                raise ValueError(f"{arch} not handled")

    def replace_typedef_struct(self, v6_lines: list[str]) -> list[str]:
        output = list()
        typedef = ""
        for line in v6_lines:
            if typedef:
                if not re.search(r"^}\s[\w_]+;", line):
                    # Skip struct content
                    continue
                type_name = re.findall(r"[\w_]+", line)[0]
                output.append(
                    f"typedef {type_name} {re.sub(self.v6_lower,self.v5_lower, type_name)};\n"
                )
                typedef = ""
                continue

            if re.search(rf"^typedef\s+(struct|union)", line):
                typedef = line
                continue
            output.append(line)
        return output

    def replace_typedef_enum(self, v6_lines: list[str]) -> list[str]:
        output = list()
        typedef = ""
        for line in v6_lines:
            if typedef:
                if not re.search(r"^}\s[\w_]+;", line):
                    # Replace name
                    if self.v6_camel not in line and self.v6_upper not in line:
                        output.append(line)
                        continue
                    found = re.findall(
                        rf"({self.v6_camel}|{self.v6_upper})([\w_]+)", line
                    )
                    entry_name: str = "".join(found[0])
                    v5_name = entry_name.replace(self.v6_camel, self.v5_upper).replace(
                        self.v6_upper, self.v5_upper
                    )
                    patched_line = re.sub(
                        rf"({self.v6_camel}|{self.v6_upper}).+",
                        f"{v5_name} = {entry_name},",
                        line,
                    )
                    output.append(patched_line)
                    continue
                # We still have LLVM and CS naming conventions mixed
                p = re.sub(self.v6_lower, self.v5_lower, line)
                p = re.sub(rf"({self.v6_camel}|{self.v6_upper})", self.v5_upper, p)
                output.append(p)
                typedef = ""
                continue

            if re.search(rf"^typedef\s+enum", line):
                typedef = line
                output.append("typedef enum {\n")
                continue
            output.append(line)
        return output

    def remove_comments(self, v6_lines: list[str]) -> list[str]:
        output = list()
        for line in v6_lines:
            if re.search(r"^\s*//", line) and "// SPDX" not in line:
                continue
            output.append(line)
        return output

    def replace_v6_prefix(self, v6_lines: list[str]) -> list[str]:
        output = list()
        in_typedef = False
        for line in v6_lines:
            if "CAPSTONE_SYSTEMZ_COMPAT_HEADER" in line:
                output.append(line)
            if in_typedef:
                if re.search(r"^}\s[\w_]+;", line):
                    in_typedef = False
                output.append(line)
                continue

            if re.search(f"^typedef", line):
                in_typedef = True
                output.append(line)
                continue
            output.append(
                re.sub(rf"({self.v6_camel}|{self.v6_upper})", self.v5_upper, line)
            )
        return output

    def replace_include_guards(self, v6_lines: list[str]) -> list[str]:
        output = list()
        skip = False
        for line in v6_lines:
            if "CAPSTONE_SYSTEMZ_COMPAT_HEADER" in line:
                # The compat heade is inlcuded in the v6 header.
                # Because v5 and v6 header share the same name.
                skip = True
                continue
            elif skip and "#endif" in line:
                skip = False
                continue
            elif skip:
                continue

            if not re.search(r"^#(ifndef|define)", line):
                output.append(line)
                continue
            output.append(re.sub(self.v6_upper, self.v5_upper, line))
        return output

    def inject_v6_header(self, v6_lines: list[str]) -> list[str]:
        output = list()
        header_inserted = False
        for line in v6_lines:
            if re.search(r"^#include", line):
                if not header_inserted:
                    output.append(f'#include "{self.v6_lower}.h"\n')
                    header_inserted = True
            output.append(line)
        return output

    def add_cc_macros(self, v6_lines: list[str]) -> list[str]:
        v6_lines += AARCH64_CC_MACROS
        return v6_lines

    def generate_v5_compat_header(self) -> bool:
        """
        Translates the aarch64.h header into the arm64.h header and renames all aarch64 occurrences.
        It does simple regex matching and replacing.
        Same for systemz.h and SYSTEMZ -> SYSZ. But the output file is systemz_compatibility.h.
        """
        log.info("Generate compatibility header")
        with open(self.v6) as f:
            v6_lines = f.readlines()

        patched = self.replace_typedef_struct(v6_lines)
        patched = self.replace_typedef_enum(patched)
        patched = self.remove_comments(patched)
        patched = self.replace_v6_prefix(patched)
        patched = self.replace_include_guards(patched)
        patched = self.inject_v6_header(patched)
        if self.v6_lower == "aarch64":
            patched = self.add_cc_macros(patched)

        with open(self.v5, "w+") as f:
            f.writelines(patched)

        if self.clang_format:
            sp.run(
                [
                    "clang-format-17",
                    "-i",
                    f"--style=file:{self.clang_format}",
                    self.v5,
                ]
            )


if __name__ == "__main__":
    args = parse_args()
    if (not args.patch and not args.compat) or (args.patch and args.compat):
        print("You need to specify either -c or -p")
        exit(1)
    if args.compat and not (args.v6 and args.v5):
        print("Generating the v5 compatibility header requires --v5 and --v6")
        exit(1)
    if args.patch and not (args.inc and args.header):
        print("Patching headers requires --inc and --header")
        exit(1)

    if args.patch:
        patcher = HeaderPatcher(args.header, args.inc)
        patcher.patch_header()
        exit(0)

    if "aarch64" in args.v6.name:
        arch = "aarch64"
    elif "systemz" in args.v6.name:
        arch = "systemz"
    else:
        raise ValueError(f"Does not know the arch for header file: {args.v6.name}")

    builder = CompatHeaderBuilder(args.v6, args.v5, arch, args.clang_format)
    builder.generate_v5_compat_header()

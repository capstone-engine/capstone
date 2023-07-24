#!/usr/bin/env python3

import argparse
import re
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="PatchHeaders",
        description="Patches generated enums into the main arch header file.",
    )
    parser.add_argument("--header", dest="header", help="Path header file.", type=Path, required=True)
    parser.add_argument("--inc", dest="inc", help="Path inc file.", type=Path, required=True)
    arguments = parser.parse_args()
    return arguments


def error_exit(msg: str) -> None:
    print(f"[x] {msg}")
    exit(1)


def patch_header(header: Path, inc: Path) -> None:
    if not (header.exists() or header.is_file()):
        error_exit(f"Header file {header.name} does not exist.")

    if not (inc.exists() or inc.is_file()):
        error_exit(f".inc file {inc.name} does not exist.")

    with open(header) as f:
        header_content = f.read()

    if inc.name not in header_content:
        error_exit(f"{inc.name} has no include comments in {header.name}")

    with open(inc) as f:
        inc_content = f.read()

    to_write: dict[str:str] = {}
    enum_vals_id = ""
    for line in inc_content.splitlines():
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
            rf"\s*// generated content <{inc.name}{header_enum_id}> begin.*(\n)"
            rf"(.*\n)+"
            rf"\s*// generated content <{inc.name}{header_enum_id}> end.*(\n)"
        )
        if not re.search(regex, header_content):
            error_exit(f"Could not locate include comments for {inc.name}")

        new_content = (
            f"\n\t// generated content <{inc.name}{header_enum_id}> begin\n"
            + "\t// clang-format off\n\n"
            + to_write[ev_id]
            + "\n\t// clang-format on\n"
            + f"\t// generated content <{inc.name}{header_enum_id}> end\n"
        )

        header_content = re.sub(regex, new_content, header_content)
    with open(header, "w") as f:
        f.write(header_content)
    print(f"[*] Patched {inc.name} into {header.name}")


if __name__ == "__main__":
    args = parse_args()
    patch_header(args.header, args.inc)

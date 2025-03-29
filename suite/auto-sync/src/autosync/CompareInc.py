#!/usr/bin/env python3

import argparse
import filecmp
import subprocess as sp
import sys
import os
import logging as log
from pathlib import Path

from autosync.Helper import convert_loglevel, fail_exit, get_path


def get_changed_files(base_ref: str, cmp_ref: str) -> list[dict]:
    result = sp.run(
        [
            "git",
            "--no-pager",
            "diff",
            "--name-only",
            base_ref,
            cmp_ref,
            "--",
            get_path("{CS_ARCH_MODULE_DIR}"),
        ],
        capture_output=True,
    )
    if result.stderr:
        fail_exit(f"git diff failed with: {result.stderr}")

    if not result.stdout:
        # Nothing changed
        log.info("No changes on .inc files.")
        return list()

    files = list()
    for file in result.stdout.decode("utf8").splitlines():
        log.info(f"{file} changed.")
        path = get_path("{CS_ROOT}").joinpath(Path(file))
        arch = path.parent.name
        # Always add all inc files to the comparison if an arch was edited.
        for inc_file in path.parent.glob("**/*.inc"):
            files.append({"arch": arch, "filename": inc_file.name})
    return files


def compare_files(changed_files: list[dict]) -> bool:
    success = True
    log.info(f"{len(changed_files)} files to compare.")
    for f in changed_files:
        in_capstone = (
            get_path("{CS_ARCH_MODULE_DIR}").joinpath(f["arch"]).joinpath(f["filename"])
        )
        generated = get_path("{C_INC_OUT_DIR}").joinpath(f["filename"])
        if not in_capstone.exists():
            log.error(f"{in_capstone} does not exist.")
            success = False
            continue
        if not generated.exists():
            log.error(f"{generated} does not exist.")
            success = False
            continue
        match = filecmp.cmp(in_capstone, generated, shallow=False)
        log.info(f"Compare: {in_capstone} - {generated} = {match}")
        if not match:
            log.error(f"Files of '{in_capstone.name}' mismatch.")
            success = False
            continue
    return success


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="CompareInc",
        description="Compare the inc files of a two git references against the actual generated ones.",
    )
    parser.add_argument(
        "-b",
        dest="base_ref",
        help="Base git reference (usually upstream/next).",
        required=True,
    )
    parser.add_argument(
        "-c",
        dest="cmp_ref",
        help="Compare git reference (usually HEAD).",
        required=True,
    )
    arguments = parser.parse_args()
    return arguments


def main():
    args = parse_args()
    log.basicConfig(
        level=convert_loglevel("info"),
        stream=sys.stdout,
        format="%(levelname)-5s - %(message)s",
        force=True,
    )
    changed_files = get_changed_files(args.base_ref, args.cmp_ref)
    if compare_files(changed_files):
        log.info("Files were correctly generated.")
        exit(0)
    log.error("If you did not change anything: please notify us.")
    fail_exit("Some files were not correctly generated.")


if __name__ == "__main__":
    main()

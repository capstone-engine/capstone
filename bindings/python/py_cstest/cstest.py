#!/usr/bin/env python3
# Copyright © 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import argparse
import logging as log
import subprocess as sp
import sys
import os
import yaml

from pathlib import Path


class TestStats:
    def __init__(self, total_file_count: int):
        self.total_file_count = total_file_count
        self.test_case_count = 0
        self.success = 0
        self.failed = 0
        self.skipped = 0
        self.error = 0
        self.invalid_files = 0
        self.err_msgs: list[str] = list()

    def add_error(self, msg: str):
        self.error += 1
        self.err_msgs.append(msg)

    def set_total_test_cases(self, total_test_cases: int):
        self.test_case_count = total_test_cases

    def get_test_case_count(self) -> int:
        return self.test_case_count


class TestCase:
    def __init__(self, test_case_dict: dict):
        self.tc_dict = test_case_dict


class TestFile:
    def __init__(self, tfile_path: Path):
        with open(tfile_path) as f:
            try:
                self.content = yaml.safe_load(f)
            except yaml.YAMLError as e:
                raise e
        self.test_cases = list()
        if not self.content:
            raise ValueError("Empty file")
        for tc_dict in self.content["test_cases"]:
            tc = TestCase(tc_dict)
            self.test_cases.append(tc)

    def num_test_cases(self) -> int:
        return len(self.test_cases)


class CSTest:
    def __init__(self, path: Path, exclude: list[Path], include: list[Path]):
        self.exclude = exclude
        self.include = include
        self.yaml_paths: list[Path] = list()

        log.info(f"Search test files in {path}")
        if path.is_file():
            self.yaml_paths.append(path)
        else:
            for root, dirs, files in os.walk(path, onerror=print):
                for file in files:
                    f = Path(root).joinpath(file)
                    if f.suffix in [".yaml", ".yml"]:
                        self.yaml_paths.append(f)

        log.info(f"Found {len(self.yaml_paths)} test files.")
        self.stats = TestStats(len(self.yaml_paths))
        self.test_files: list[TestFile] = list()

    def parse_files(self):
        total_test_cases = 0
        total_files = len(self.yaml_paths)
        count = 1
        for tfile in self.yaml_paths:
            print(f"Parse {count}/{total_files}: {tfile.name}", end=f"{' ' * 20}\r", flush=True)
            try:
                tf = TestFile(tfile)
                total_test_cases += tf.num_test_cases()
                self.test_files.append(tf)
            except (yaml.YAMLError, ValueError) as e:
                self.stats.add_error(str(e))
                log.error(f"Invalid YAML file: {tfile}")
            finally:
                count += 1
        self.stats.set_total_test_cases(total_test_cases)
        log.info(f"Found {self.stats.get_test_case_count()} test cases.")

    def run_tests(self):
        self.parse_files()


def get_repo_root() -> str | None:
    res = sp.run(["git", "rev-parse", "--show-toplevel"], capture_output=True)
    if res.stderr:
        log.error("Could not get repository root directory.")
        return None
    return res.stdout.decode("utf8").strip()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Python CSTest",
        description="Pyton binding cstest implementation.",
    )
    repo_root = get_repo_root()
    if repo_root:
        parser.add_argument(
            "-d",
            dest="search_dir",
            help="Directory to search for .yaml test files.",
            default=Path(f"{repo_root}/tests/"),
            type=Path,
        )
    else:
        parser.add_argument(
            "-d",
            dest="search_dir",
            help="Directory to search for .yaml test files.",
            required=True,
            type=Path,
        )
    parser.add_argument(
        "-e",
        dest="exclude",
        help="List of file names to exclude.",
        nargs="+",
        required=False,
        default=list(),
    )
    parser.add_argument(
        "-i",
        dest="include",
        help="List of file names to include.",
        nargs="+",
        required=False,
        default=list(),
    )
    parser.add_argument(
        "-v",
        dest="verbosity",
        help="Verbosity of the log messages.",
        choices=["debug", "info", "warning", "error", "fatal", "critical"],
        default="info",
    )
    arguments = parser.parse_args()
    return arguments


if __name__ == "__main__":
    log_levels = {
        "debug": log.DEBUG,
        "info": log.INFO,
        "warning": log.WARNING,
        "error": log.ERROR,
        "fatal": log.FATAL,
        "critical": log.CRITICAL,
    }
    args = parse_args()
    log.basicConfig(
        level=log_levels[args.verbosity],
        stream=sys.stdout,
        format="%(levelname)-5s - %(message)s",
        force=True,
    )
    CSTest(args.search_dir, args.exclude, args.include).run_tests()

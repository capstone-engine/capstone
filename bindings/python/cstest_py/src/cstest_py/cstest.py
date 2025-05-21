#!/usr/bin/env python3
# Copyright © 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

# Typing for Python3.8
from __future__ import annotations

import argparse
import logging
import sys
import os
import yaml
import capstone
import traceback

from capstone import CsInsn, Cs, CS_ARCH_AARCH64, CS_MODE_64, CS_MODE_16

from cstest_py.cs_modes import configs
from cstest_py.details import compare_details
from cstest_py.compare import (
    compare_asm_text,
    compare_str,
    compare_tbool,
    compare_enum,
)
from enum import Enum
from pathlib import Path

log = logging.getLogger("__name__")


def get_cs_int_attr(cs, attr: str, err_msg_pre: str):
    try:
        attr_int = getattr(cs, attr)
        if not isinstance(attr_int, int):
            raise AttributeError(f"{attr} not found")
        return attr_int
    except AttributeError:
        log.warning(f"{err_msg_pre}: Capstone doesn't have the attribute '{attr}'")
        return None


def arch_bits(arch: int, mode: int) -> int:
    if arch == CS_ARCH_AARCH64 or mode & CS_MODE_64:
        return 64
    elif mode & CS_MODE_16:
        return 16
    return 32


class TestResult(Enum):
    SUCCESS = 0
    FAILED = 1
    SKIPPED = 2
    ERROR = 3


class TestStats:
    def __init__(self, total_file_count: int):
        self.total_file_count = total_file_count
        self.valid_test_files = 0
        self.test_case_count = 0
        self.success = 0
        self.failed = 0
        self.skipped = 0
        self.errors = 0
        self.invalid_files = 0
        self.total_valid_files = 0
        self.err_msgs: list[str] = list()
        self.failing_files = set()

    def add_failing_file(self, test_file: Path):
        self.failing_files.add(test_file)

    def add_error_msg(self, msg: str):
        self.err_msgs.append(msg)

    def add_invalid_file_dp(self, tfile: Path):
        self.invalid_files += 1
        self.errors += 1
        self.add_failing_file(tfile)

    def add_test_case_data_point(self, dp: TestResult):
        if dp == TestResult.SUCCESS:
            self.success += 1
        elif dp == TestResult.FAILED:
            self.failed += 1
        elif dp == TestResult.SKIPPED:
            self.skipped += 1
        elif dp == TestResult.ERROR:
            self.errors += 1
            self.failed += 1
        else:
            raise ValueError(f"Unhandled TestResult: {dp}")

    def set_total_valid_files(self, total_valid_files: int):
        self.total_valid_files = total_valid_files

    def set_total_test_cases(self, total_test_cases: int):
        self.test_case_count = total_test_cases

    def get_test_case_count(self) -> int:
        return self.test_case_count

    def print_evaluate(self):
        if self.total_file_count == 0:
            log.error("No test files found!")
            exit(-1)
        if self.test_case_count == 0:
            log.error("No test cases found!")
            exit(-1)
        if self.failing_files:
            print("Test files with failures:")
            for tf in self.failing_files:
                print(f" - {tf}")
            print()
        if self.err_msgs:
            print("Error messages:")
            for error in self.err_msgs:
                print(f" - {error}")

        print("\n-----------------------------------------")
        print("Test run statistics\n")
        print(f"Valid files: {self.total_valid_files}")
        print(f"Invalid files: {self.invalid_files}")
        print(f"Errors: {self.errors}\n")
        print("Test cases:")
        print(f"\tTotal: {self.test_case_count}")
        print(f"\tSuccessful: {self.success}")
        print(f"\tSkipped: {self.skipped}")
        print(f"\tFailed: {self.failed}")
        print("-----------------------------------------")
        print("")

        if self.test_case_count != self.success + self.failed + self.skipped:
            log.error(
                "Inconsistent statistics: total != successful + failed + skipped\n"
            )

        if self.errors != 0:
            log.error("Failed with errors\n")
            exit(-1)
        elif self.failed != 0:
            log.warning("Not all tests succeeded\n")
            exit(-1)
        log.info("All tests succeeded.\n")
        exit(0)


class TestInput:
    def __init__(self, input_dict: dict):
        self.input_dict = input_dict
        if "bytes" not in self.input_dict:
            raise ValueError("Error: 'Missing required mapping field'\nField: 'bytes'.")
        if "options" not in self.input_dict:
            raise ValueError(
                "Error: 'Missing required mapping field'\nField: 'options'."
            )
        if "arch" not in self.input_dict:
            raise ValueError("Error: 'Missing required mapping field'\nField: 'arch'.")
        self.in_bytes = bytes(self.input_dict["bytes"])
        self.options = self.input_dict["options"]
        self.arch = self.input_dict["arch"]

        self.name = "" if "name" not in self.input_dict else self.input_dict["name"]
        if "address" not in self.input_dict:
            self.address: int = 0
        else:
            assert isinstance(self.input_dict["address"], int)
            self.address = self.input_dict["address"]
        self.handle = None
        self.arch_bits = 0

    def setup(self):
        log.debug(f"Init {self}")
        arch = get_cs_int_attr(capstone, self.arch, "CS_ARCH")
        if arch is None:
            cs_name = f"CS_ARCH_{self.arch.upper()}"
            arch = get_cs_int_attr(capstone, cs_name, "CS_ARCH")
            if arch is None:
                raise ValueError(
                    f"Couldn't init architecture as '{self.arch}' or '{cs_name}'.\n"
                    f"'{self.arch}' is not mapped to a capstone architecture."
                )
        new_mode = 0
        for opt in self.options:
            if "CS_MODE_" in opt:
                mode = get_cs_int_attr(capstone, opt, "CS_OPT")
                if mode is not None:
                    new_mode |= mode
                    continue
        self.handle = Cs(arch, new_mode)

        for opt in self.options:
            if "CS_MODE_" in opt:
                continue
            if "CS_OPT_" in opt and opt in configs:
                mtype = configs[opt]["type"]
                val = configs[opt]["val"]
                self.handle.option(mtype, val)
                continue
            log.warning(f"Option: '{opt}' not used")

        self.arch_bits = arch_bits(self.handle.arch, self.handle.mode)
        log.debug("Init done")

    def decode(self) -> list[CsInsn]:
        if not self.handle:
            raise ValueError("self.handle is None. Must be setup before.")
        return [i for i in self.handle.disasm(self.in_bytes, self.address)]

    def __str__(self):
        default = (
            f"TestInput {{ arch: {self.arch}, options: {self.options}, "
            f"addr: {self.address:x}, bytes: [ {','.join([f'{b:#04x}' for b in self.in_bytes])} ] }}"
        )
        if self.name:
            return f"{self.name} -- {default}"
        return default


class TestExpected:
    def __init__(self, expected_dict: dict):
        self.expected_dict = expected_dict
        self.insns = (
            list() if "insns" not in self.expected_dict else self.expected_dict["insns"]
        )

    def compare(self, actual_insns: list[CsInsn], bits: int) -> TestResult:
        if len(actual_insns) != len(self.insns):
            log.error(
                "Number of decoded instructions don't match (actual != expected): "
                f"{len(actual_insns)} != {len(self.insns):#x}"
            )
            return TestResult.FAILED
        for a_insn, e_insn in zip(actual_insns, self.insns):
            if not compare_asm_text(
                a_insn,
                e_insn.get("asm_text"),
                bits,
            ):
                return TestResult.FAILED

            if not compare_str(a_insn.mnemonic, e_insn.get("mnemonic"), "mnemonic"):
                return TestResult.FAILED

            if not compare_str(a_insn.op_str, e_insn.get("op_str"), "op_str"):
                return TestResult.FAILED

            if not compare_enum(a_insn.id, e_insn.get("id"), "id"):
                return TestResult.FAILED

            if not compare_tbool(a_insn.is_alias, e_insn.get("is_alias"), "is_alias"):
                return TestResult.FAILED

            if not compare_tbool(a_insn.illegal, e_insn.get("illegal"), "illegal"):
                return TestResult.FAILED

            if not compare_enum(a_insn.alias_id, e_insn.get("alias_id"), "alias_id"):
                return TestResult.FAILED

            if not compare_details(a_insn, e_insn.get("details")):
                return TestResult.FAILED
        return TestResult.SUCCESS


class TestCase:
    def __init__(self, test_case_dict: dict):
        self.tc_dict = test_case_dict
        if "input" not in self.tc_dict:
            raise ValueError("Mandatory field 'input' missing")
        if "expected" not in self.tc_dict:
            raise ValueError("Mandatory field 'expected' missing")
        self.input = TestInput(self.tc_dict["input"])
        self.expected = TestExpected(self.tc_dict["expected"])
        self.skip = "skip" in self.tc_dict
        if self.skip and "skip_reason" not in self.tc_dict:
            raise ValueError(
                "If 'skip' field is set a 'skip_reason' field must be set as well."
            )
        self.skip_reason = (
            self.tc_dict["skip_reason"] if "skip_reason" in self.tc_dict else ""
        )

    def __str__(self) -> str:
        return f"{self.input}"

    def test(self) -> TestResult:
        if self.skip:
            log.info(f"Skip {self}\nReason: {self.skip_reason}")
            return TestResult.SKIPPED

        try:
            self.input.setup()
        except Exception as e:
            log.error(f"Setup failed at with: {e}")
            traceback.print_exc()
            return TestResult.ERROR

        try:
            insns = self.input.decode()
        except Exception as e:
            log.error(f"Decode failed with: {e}")
            traceback.print_exc()
            return TestResult.ERROR

        try:
            return self.expected.compare(insns, self.input.arch_bits)
        except Exception as e:
            log.error(f"Compare expected failed with: {e}")
            traceback.print_exc()
            return TestResult.ERROR


class TestFile:
    def __init__(self, tfile_path: Path):
        self.path = tfile_path
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

    def __str__(self) -> str:
        return f"{self.path}"


class CSTest:
    def __init__(self, path: Path, exclude: list[Path], include: list[Path]):
        self.yaml_paths: list[Path] = list()

        log.info(f"Search test files in {path}")
        if path.is_file():
            self.yaml_paths.append(path)
        else:
            for root, dirs, files in os.walk(path, onerror=print):
                for file in files:
                    f = Path(root).joinpath(file)
                    if f.suffix not in [".yaml", ".yml"]:
                        continue
                    if f.name in exclude:
                        continue
                    if not include or f.name in include:
                        log.debug(f"Add: {f}")
                        self.yaml_paths.append(f)

        log.info(f"Test files found: {len(self.yaml_paths)}")
        self.stats = TestStats(len(self.yaml_paths))
        self.test_files: list[TestFile] = list()

    def parse_files(self):
        total_test_cases = 0
        total_files = len(self.yaml_paths)
        count = 1
        for tfile in self.yaml_paths:
            print(
                f"Parse {count}/{total_files}: {tfile.name}",
                end=f"{' ' * 20}\r",
                flush=True,
            )
            try:
                tf = TestFile(tfile)
                total_test_cases += tf.num_test_cases()
                self.test_files.append(tf)
            except yaml.YAMLError as e:
                self.stats.add_error_msg(str(e))
                self.stats.add_invalid_file_dp(tfile)
                log.error("Error: 'libyaml parser error'")
                log.error(f"{e}")
                log.error(f"Failed to parse test file '{tfile}'")
            except ValueError as e:
                self.stats.add_error_msg(str(e))
                self.stats.add_invalid_file_dp(tfile)
                log.error(f"Error: ValueError: {e}")
                log.error(f"Failed to parse test file '{tfile}'")
            finally:
                count += 1
        self.stats.set_total_valid_files(len(self.test_files))
        self.stats.set_total_test_cases(total_test_cases)
        log.info(f"Found {self.stats.get_test_case_count()} test cases.{' ' * 20}")

    def run_tests(self):
        self.parse_files()
        for tf in self.test_files:
            log.info(f"Test file: {tf}\n")
            for tc in tf.test_cases:
                log.info(f"Run test: {tc}")
                try:
                    result = tc.test()
                except Exception as e:
                    result = TestResult.ERROR
                    self.stats.add_error_msg(str(e))
                if result == TestResult.FAILED or result == TestResult.ERROR:
                    self.stats.add_failing_file(tf.path)
                self.stats.add_test_case_data_point(result)
                log.info(result)
                print()
        self.stats.print_evaluate()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="Python CSTest",
        description="Python binding cstest implementation.",
    )
    parser.add_argument(
        dest="search_dir",
        help="Directory to search for .yaml test files.",
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


def main():
    log_levels = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "fatal": logging.FATAL,
        "critical": logging.CRITICAL,
    }
    args = parse_args()
    format = logging.Formatter("%(levelname)-5s - %(message)s", None, "%")
    log.setLevel(log_levels[args.verbosity])

    h1 = logging.StreamHandler(sys.stdout)
    h1.addFilter(
        lambda record: record.levelno >= log_levels[args.verbosity]
        and record.levelno < logging.WARNING
    )
    h1.setFormatter(format)

    h2 = logging.StreamHandler(sys.stderr)
    h2.setLevel(logging.WARNING)
    h2.setFormatter(format)

    log.addHandler(h1)
    log.addHandler(h2)
    CSTest(args.search_dir, args.exclude, args.include).run_tests()


if __name__ == "__main__":
    main()

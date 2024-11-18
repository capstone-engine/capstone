#!/usr/bin/env python3

# Copyright © 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

# Typing for Python3.8
from __future__ import annotations
import sys
import subprocess as sp
from pathlib import Path


def check(cmd: list[str], expected_stdout: str, expected_stderr: str, fail_msg: str):
    print(f"Run: {' '.join(cmd)}")
    result = sp.run(cmd, capture_output=True)
    stderr = result.stderr.decode("utf8")
    stdout = result.stdout.decode("utf8")
    if expected_stderr and expected_stderr not in stderr:
        print(f"STDERR mismatch: '{expected_stderr}' not in stderr")
        print("\n###################### STDERR ######################\n")
        print(stderr)
        print("####################################################\n")
        print(fail_msg)
        exit(1)
    if expected_stdout and expected_stdout not in stdout:
        print(f"STDOUT mismatch: '{expected_stdout}' not in stdout")
        print("\n###################### STDOUT ######################\n")
        print(stdout)
        print("####################################################\n")
        print(fail_msg)
        exit(1)


def run_tests(cmd: str):
    path = Path(__file__).parent.resolve()
    cmd = cmd.split(" ")
    check(
        cmd + [f"{path.joinpath('empty_test_file.yaml')}"],
        expected_stderr="Failed to parse test file ",
        expected_stdout="",
        fail_msg="Failed the empty file test",
    )

    check(
        cmd + [f"{path.joinpath('missing_madatory_field.yaml')}"],
        expected_stderr="Error: 'Missing required mapping field'",
        expected_stdout="",
        fail_msg="Failed the mandatory field test",
    )

    check(
        cmd + [f"{path.joinpath('invalid_test_file.yaml')}"],
        expected_stderr="Error: 'libyaml parser error'",
        expected_stdout="",
        fail_msg="Failed the invalid test file test",
    )

    check(
        cmd + [f"{path.joinpath('min_valid_test_file.yaml')}"],
        expected_stdout="All tests succeeded.",
        expected_stderr="",
        fail_msg="Failed the minimal valid parsing test",
    )

    check(
        cmd + [f"{path.joinpath('invalid_cs_input.yaml')}"],
        expected_stderr="'ar' is not mapped to a capstone architecture.",
        expected_stdout="",
        fail_msg="Test: Invalid CS option failed",
    )

    check(
        cmd + [f"{path.joinpath('invalid_cs_input.yaml')}"],
        expected_stderr="0 != 0x1",
        expected_stdout="",
        fail_msg="Test: Wrong number of instruction disassembled failed",
    )

    check(
        cmd + [f"{path.joinpath('invalid_cs_input.yaml')}"],
        expected_stderr="Option: 'thum' not used",
        expected_stdout="",
        fail_msg="Test: Invalid disassembly due to wrong option failed",
    )

    check(
        cmd + [f"{path}"],
        expected_stdout="Test files found: 6",
        expected_stderr="",
        fail_msg="Test: Detecting file in directory failed.",
    )

    if "cstest_py" in cmd:
        check(
            cmd
            + [
                f"{path}",
                "-e",
                "invalid_cs_input.yaml",
                "-i",
                "invalid_cs_input.yaml",
                "min_valid_test_file.yaml",
                "-v",
                "debug",
            ],
            expected_stdout="Test files found: 2",
            expected_stderr="",
            fail_msg="Test: Detecting file in directory failed.",
        )


def print_usage_exit():
    print(f'{sys.argv[0]} "cstest_command"')
    print('"cstest_command" examples:')
    print('\t"python3 ../../bindings/python/cstest.py"')
    print("\tcstest")
    exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print_usage_exit()

    run_tests(sys.argv[1])
    print("All tests passed")
    exit(0)

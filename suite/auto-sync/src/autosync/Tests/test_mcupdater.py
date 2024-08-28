# SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import logging
import os
import sys
import unittest
from pathlib import Path

from autosync.Helper import get_path, test_only_overwrite_path_var
from autosync.MCUpdater import MCUpdater


class TestHeaderPatcher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        logging.basicConfig(
            level=logging.DEBUG,
            stream=sys.stdout,
            format="%(levelname)-5s - %(message)s",
            force=True,
        )

    def test_test_case_gen(self):
        """
        To enforce sequential execution of the tests, we execute them in here.
        And don't make them a separated test.
        """
        self.assertTrue(self.unified_test_cases(), "Failed: unified_test_cases")
        self.assertTrue(self.separated_test_cases(), "Failed: separated_test_cases")
        self.assertTrue(
            self.multi_mode_unified_test_cases(),
            "Failed: multi_mode_unified_test_cases",
        )
        self.assertTrue(
            self.multi_mode_separated_test_cases(),
            "Failed: multi_mode_separated_test_cases",
        )

    def unified_test_cases(self):
        out_dir = Path(
            get_path("{MCUPDATER_TEST_OUT_DIR}").joinpath("merged").joinpath("unified")
        )
        if not out_dir.exists():
            out_dir.mkdir(parents=True)
        for file in out_dir.iterdir():
            logging.debug(f"Delete old file: {file}")
            os.remove(file)
        test_only_overwrite_path_var(
            "{MCUPDATER_OUT_DIR}",
            out_dir,
        )
        self.updater = MCUpdater("ARCH", get_path("{MCUPDATER_TEST_DIR}"), [], [], True)
        self.updater.gen_all()
        return self.compare_files(out_dir, ["test_a.txt.yaml", "test_b.txt.yaml"])

    def separated_test_cases(self):
        out_dir = Path(
            get_path("{MCUPDATER_TEST_OUT_DIR}")
            .joinpath("merged")
            .joinpath("separated")
        )
        if not out_dir.exists():
            out_dir.mkdir(parents=True)
        for file in out_dir.iterdir():
            logging.debug(f"Delete old file: {file}")
            os.remove(file)
        test_only_overwrite_path_var(
            "{MCUPDATER_OUT_DIR}",
            out_dir,
        )
        self.updater = MCUpdater(
            "ARCH", get_path("{MCUPDATER_TEST_DIR}"), [], [], False
        )
        self.updater.gen_all()
        return self.compare_files(out_dir, ["test_a.txt.yaml", "test_b.txt.yaml"])

    def multi_mode_unified_test_cases(self):
        out_dir = Path(
            get_path("{MCUPDATER_TEST_OUT_DIR}").joinpath("multi").joinpath("unified")
        )
        if not out_dir.exists():
            out_dir.mkdir(parents=True)
        for file in out_dir.iterdir():
            logging.debug(f"Delete old file: {file}")
            os.remove(file)
        test_only_overwrite_path_var(
            "{MCUPDATER_OUT_DIR}",
            out_dir,
        )
        self.updater = MCUpdater(
            "ARCH", get_path("{MCUPDATER_TEST_DIR}"), [], [], True, multi_mode=True
        )
        self.updater.gen_all()
        return self.compare_files(
            out_dir,
            [
                "test_a_aarch64_v8a__fp_armv8.txt.yaml",
                "test_a_arm64_v8.2a.txt.yaml",
                "test_b_arm64.txt.yaml",
            ],
        )

    def multi_mode_separated_test_cases(self):
        out_dir = Path(
            get_path("{MCUPDATER_TEST_OUT_DIR}").joinpath("multi").joinpath("separated")
        )
        if not out_dir.exists():
            out_dir.mkdir(parents=True)
        for file in out_dir.iterdir():
            logging.debug(f"Delete old file: {file}")
            os.remove(file)
        test_only_overwrite_path_var(
            "{MCUPDATER_OUT_DIR}",
            out_dir,
        )
        self.updater = MCUpdater(
            "ARCH", get_path("{MCUPDATER_TEST_DIR}"), [], [], False, multi_mode=True
        )
        self.updater.gen_all()
        return self.compare_files(
            out_dir,
            [
                "test_a_aarch64_v8a__fp_armv8.txt.yaml",
                "test_a_arm64_v8.2a.txt.yaml",
                "test_b_arm64.txt.yaml",
            ],
        )

    def test_no_symbol_tests(self):
        out_dir = Path(get_path("{MCUPDATER_TEST_OUT_DIR}").joinpath("no_symbol"))
        if not out_dir.exists():
            out_dir.mkdir(parents=True)
        for file in out_dir.iterdir():
            logging.debug(f"Delete old file: {file}")
            os.remove(file)
        test_only_overwrite_path_var(
            "{MCUPDATER_OUT_DIR}",
            out_dir,
        )
        self.updater = MCUpdater(
            "ARCH",
            get_path("{MCUPDATER_TEST_DIR}"),
            [],
            [],
            False,
        )
        self.updater.gen_all()
        self.assertFalse(
            out_dir.joinpath("test_no_symbol.s.txt.yaml").exists(),
            "File should not exist",
        )

    def compare_files(self, out_dir: Path, filenames: list[str]) -> bool:
        if not out_dir.is_dir():
            logging.error(f"{out_dir} is not a directory.")
            return False

        parent_name = out_dir.parent.name
        expected_dir = (
            get_path("{MCUPDATER_TEST_DIR_EXPECTED}")
            .joinpath(parent_name)
            .joinpath(out_dir.name)
        )
        if not expected_dir.exists() or not expected_dir.is_dir():
            logging.error(f"{expected_dir} is not a directory.")
            return False
        for file in filenames:
            efile = expected_dir.joinpath(file)
            if not efile.exists():
                logging.error(f"{efile} does not exist")
                return False
            with open(efile) as f:
                logging.debug(f"Read {efile}")
                expected = f.read()

            afile = out_dir.joinpath(file)
            if not afile.exists():
                logging.error(f"{afile} does not exist")
                return False
            with open(afile) as f:
                logging.debug(f"Read {afile}")
                actual = f.read()
            if expected != actual:
                logging.error("Files mismatch")
                print(f"Expected: {efile}")
                print(f"Actual: {afile}\n")
                print(f"Expected:\n\n{expected}\n")
                print(f"Actual:\n\n{actual}\n")
                return False
            logging.debug(f"OK: actual == expected")
        return True

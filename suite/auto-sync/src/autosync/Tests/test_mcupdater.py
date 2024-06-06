# SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3
import logging
import sys
import unittest

from autosync.Helper import get_path
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
        cls.updater = MCUpdater(
            "ARCH", get_path("{MCUPDATER_TEST_DIR}"), [r".*\.cs"], None
        )

    def test_parsing(self):
        self.updater.included.append("test_a.txt")
        self.updater.gen_tests_in_dir(self.updater.mc_dir)
        self.assertEqual(len(self.updater.test_files), 1)
        self.assertListEqual(
            self.updater.test_files["test_a.txt"].mattrs, ["mattr=+v8.1a", "mattr=+crc"]
        )
        self.assertEqual(len(self.updater.test_files["test_a.txt"].tests), 24)
        self.assertEqual(
            self.updater.test_files["test_a.txt"].manager.get_num_incomplete(), 0
        )
        with open(get_path("{MCUPDATER_TEST_DIR}").joinpath("test_a.txt.cs")) as f:
            correct = f.read()
        self.assertEqual(
            correct, self.updater.test_files["test_a.txt"].get_cs_testfile_content()
        )

    def test_adding_header_from_mc(self):
        self.updater = MCUpdater(
            arch="ARM",
            mc_dir=get_path("{MCUPDATER_TEST_DIR}"),
            excluded=[r".*\.cs"],
            included=None,
        )
        self.updater.gen_tests_in_dir(self.updater.mc_dir)
        self.assertEqual(len(self.updater.test_files), 3)
        self.assertListEqual(self.updater.test_files["cps.s"].mattrs, [])
        self.assertEqual(len(self.updater.test_files["cps.s"].tests), 1)
        self.assertEqual(
            self.updater.test_files["cps.s"].manager.get_num_incomplete(), 0
        )
        with open(get_path("{MCUPDATER_TEST_DIR}").joinpath("cps.s.cs")) as f:
            correct = f.read()
        self.assertEqual(
            correct, self.updater.test_files["cps.s"].get_cs_testfile_content()
        )

# SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import unittest

from autosync.Helper import get_path
from autosync.MCUpdater import MCUpdater


class TestHeaderPatcher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.updater = MCUpdater(
            "ARCH", get_path("{MCUPDATER_TEST_DIR}"), [r".*\.cs"], list()
        )

    def test_parsing(self):
        self.updater.gen_tests_in_dir(self.updater.mc_dir)
        self.assertEqual(len(self.updater.test_files), 3)
        self.assertListEqual(
            self.updater.test_files["test_a.txt"].mattrs, ["mattr=+v8.1a", "mattr=+crc"]
        )
        self.assertEqual(len(self.updater.test_files["test_a.txt"].tests), 22)
        self.assertEqual(
            self.updater.test_files["test_a.txt"].manager.get_num_incomplete(), 0
        )
        with open(get_path("{MCUPDATER_TEST_DIR}").joinpath("test_a.txt.cs")) as f:
            correct = f.read()
        self.assertEqual(
            correct, self.updater.test_files["test_a.txt"].get_cs_testfile_content()
        )

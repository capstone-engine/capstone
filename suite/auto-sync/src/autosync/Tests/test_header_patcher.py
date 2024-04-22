# SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import unittest

from autosync.HeaderPatcher import HeaderPatcher
from autosync.Helper import get_path


class TestHeaderPatcher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hpatcher = HeaderPatcher(
            get_path("{HEADER_PATCHER_TEST_HEADER_FILE}"),
            get_path("{HEADER_PATCHER_TEST_INC_FILE}"),
            write_file=False,
        )

    def test_header_patching(self):
        self.hpatcher.patch_header()
        self.assertEqual(
            self.hpatcher.patched_header_content,
            (
                "// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>\n"
                "// SPDX-License-Identifier: BSD-3\n"
                "\n"
                "\n"
                "	// Include the whole file\n"
                "	// generated content <test_include.inc> begin\n"
                "	// clang-format off\n"
                "\n"
                "This part should be included if the whole file is included.\n"
                "\n"
                "	// clang-format on\n"
                "	// generated content <test_include.inc> end\n"
                "\n"
                "	// Include only a part of the file.\n"
                "	// generated content <test_include.inc:GUARD> begin\n"
                "	// clang-format off\n"
                "\n"
                "	Partial include of something\n"
                "\n"
                "	// clang-format on\n"
                "	// generated content <test_include.inc:GUARD> end\n"
                "\n"
            ),
        )

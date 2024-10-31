# SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import unittest

from tree_sitter import Node

from autosync.cpptranslator.Configurator import Configurator
from autosync.cpptranslator.Differ import ApplyType, Differ, Patch, PatchCoord
from autosync.cpptranslator.TemplateCollector import TemplateCollector

from autosync.Helper import get_path


class TestHeaderPatcher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configurator = Configurator("ARCH", get_path("{DIFFER_TEST_CONFIG_FILE}"))
        cls.ts_cpp_lang = configurator.get_cpp_lang()
        cls.parser = configurator.get_parser()
        cls.template_collector = TemplateCollector(
            configurator.get_parser(), configurator.get_cpp_lang(), [], []
        )
        cls.differ = Differ(configurator, testing=True, no_auto_apply=True)
        cls.maxDiff = 10000

    def check_persistence(self, nid, expected, apply_type, edited_text):
        new_node: Node = self.new_nodes[nid] if nid in self.new_nodes else None
        old_node: Node = self.old_nodes[nid] if nid in self.old_nodes else None
        if not new_node:
            before_old_node = old_node.start_byte - 1
            coord = PatchCoord(
                before_old_node,
                before_old_node,
                (before_old_node, before_old_node),
                (before_old_node, before_old_node),
            )
        else:
            coord = PatchCoord(
                new_node.start_byte,
                new_node.end_byte,
                new_node.start_point,
                new_node.end_point,
            )
        patch = Patch(
            node_id=nid,
            old=old_node.text if old_node else b"",
            new=new_node.text if new_node else b"",
            coord=coord,
            apply=apply_type,
            edit=edited_text,
        )
        self.assertEqual(patch.get_persist_info(), expected)

    def parse_files(self, filename: str):
        self.old_nodes = self.differ.parse_file(
            get_path("{DIFFER_TEST_OLD_SRC_DIR}").joinpath(filename)
        )
        self.new_nodes = self.differ.parse_file(
            get_path("{DIFFER_TEST_NEW_SRC_DIR}").joinpath(filename)
        )

    def test_patch_persistence(self):
        self.parse_files("diff_test_file.c")

        nid = "function_b"
        expected = {
            f"{nid}": {
                "apply_type": "OLD",
                "edit": "aaaaaaa",
                "new_hash": "e5b3e0e5c6fb1f5f39e5725e464e6dfa3c6a7f1a8a5d104801e1fc10b6f1cc2b",
                "old_hash": "8fc2b2123209c37534bb60c8e38564ed773430b9fc5bca37a0ae73a64b2883ab",
            }
        }
        edited_text: bytes = b"aaaaaaa"
        self.check_persistence(nid, expected, ApplyType.OLD, edited_text)

        nid = "only_in_old_I"
        expected = {
            f"{nid}": {
                "apply_type": "NEW",
                "edit": "",
                "new_hash": "",
                "old_hash": "37431b6fe6707794a8e07902bef6510fc1d10b833db9b1dccc70b1530997b2b1",
            }
        }
        self.check_persistence(nid, expected, ApplyType.NEW, b"")
        self.assertRaises(
            NotImplementedError,
            self.check_persistence,
            nid=nid,
            expected=expected,
            apply_type=ApplyType.SAVED,
            edited_text=b"",
        )

        nid = "function_b"
        expected = {
            f"{nid}": {
                "apply_type": "EDIT",
                "edit": "aaaaaaa\n\n\n\n\n91928",
                "new_hash": "e5b3e0e5c6fb1f5f39e5725e464e6dfa3c6a7f1a8a5d104801e1fc10b6f1cc2b",
                "old_hash": "8fc2b2123209c37534bb60c8e38564ed773430b9fc5bca37a0ae73a64b2883ab",
            }
        }
        edited_text: bytes = b"aaaaaaa\n\n\n\n\n91928"
        self.check_persistence(nid, expected, ApplyType.EDIT, edited_text)

    def test_patching(self):
        self.differ.diff(user_choices=list("nnnnnnnnnnnnnnnnnnnnnnnnn"))
        for efile in get_path("{DIFFER_TEST_EXPECTED_DIR}").iterdir():
            with open(efile) as f:
                expected = f.read()
            with open(get_path("{DIFFER_TEST_OUTPUT_DIR}").joinpath(efile.name)) as f:
                actual = f.read()
            print(f"Compare {efile}")
            self.assertEqual(expected, actual)

# SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import unittest
from pathlib import Path

from autosync.Helper import get_path
from autosync.cpptranslator import CppTranslator
from autosync.cpptranslator.Configurator import Configurator
from autosync.cpptranslator.patches.AddCSDetail import AddCSDetail
from autosync.cpptranslator.patches.InlineToStaticInline import InlineToStaticInline
from autosync.cpptranslator.patches.PrintRegImmShift import PrintRegImmShift
from autosync.cpptranslator.patches.Data import Data


class TestCppTranslator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configurator = Configurator("ARCH", get_path("{PATCHES_TEST_CONFIG}"))
        cls.translator = CppTranslator.Translator(configurator, False)

    def test_patching_constraints(self):
        self.translator.current_src_path_in = Path("Random_file.cpp")
        patch_add_cs_detail = AddCSDetail(0, "ARCH")
        patch_inline_to_static_inline = InlineToStaticInline(0)
        patch_print_reg_imm_shift = PrintRegImmShift(0)
        patch_data = Data(0)

        self.assertFalse(self.translator.apply_patch(patch_add_cs_detail))
        self.assertFalse(self.translator.apply_patch(patch_inline_to_static_inline))
        self.assertFalse(self.translator.apply_patch(patch_print_reg_imm_shift))
        self.assertTrue(self.translator.apply_patch(patch_data))

        self.translator.current_src_path_in = Path("ARMInstPrinter.cpp")
        self.assertTrue(self.translator.apply_patch(patch_add_cs_detail))
        self.assertFalse(self.translator.apply_patch(patch_inline_to_static_inline))
        self.assertTrue(self.translator.apply_patch(patch_print_reg_imm_shift))
        self.assertTrue(self.translator.apply_patch(patch_data))

        self.translator.current_src_path_in = Path("ARMAddressingModes.h")
        self.assertFalse(self.translator.apply_patch(patch_add_cs_detail))
        self.assertTrue(self.translator.apply_patch(patch_inline_to_static_inline))
        self.assertFalse(self.translator.apply_patch(patch_print_reg_imm_shift))
        self.assertTrue(self.translator.apply_patch(patch_data))

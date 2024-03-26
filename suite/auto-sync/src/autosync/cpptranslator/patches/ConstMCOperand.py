# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class ConstMCOperand(Patch):
    """
    Patch   const MCOperand ...
    to      MCOperand

    Removes the const qualifier from MCOperand declarations. They are ignored by the following functions.
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(declaration"
            "   (type_qualifier)"
            '   ((type_identifier) @tid (#eq? @tid "MCOperand"))'
            "   (init_declarator) @init_decl"
            ") @const_mcoperand"
        )

    def get_main_capture_name(self) -> str:
        return "const_mcoperand"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        init_decl = captures[2][0]
        init_decl = get_text(src, init_decl.start_byte, init_decl.end_byte)
        return b"MCOperand " + init_decl + b";"

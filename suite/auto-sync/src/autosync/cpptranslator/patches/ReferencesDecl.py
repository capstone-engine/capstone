# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import re

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class ReferencesDecl(Patch):
    """
    Patch   TYPE &Param
    to      TYPE *Param

    Param is optional
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "["
            "(reference_declarator)"
            "(type_identifier) (abstract_reference_declarator)"
            "] @reference_decl"
        )

    def get_main_capture_name(self) -> str:
        return "reference_decl"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        ref_decl: Node = captures[0][0]
        ref_decl_text = get_text(src, ref_decl.start_byte, ref_decl.end_byte)

        res = re.sub(rb"&", b"*", ref_decl_text)
        return res

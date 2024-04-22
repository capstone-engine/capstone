# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class IsPredicate(Patch):
    """
    Patch   OpInfo[i].isPredicate()
    to      MCOperandInfo_isPredicate(&OpInfo[i])
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(call_expression"
            "   (field_expression"
            "       (subscript_expression"
            "           ((identifier) @op_info_var)"
            "           ((_) @index)"
            "       )"
            '       ((field_identifier) @fid (#eq? @fid "isPredicate"))'
            "   )"
            ") @is_predicate"
        )

    def get_main_capture_name(self) -> str:
        return "is_predicate"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        op_info_var = captures[1][0]
        index = captures[2][0]
        op_info_var = get_text(src, op_info_var.start_byte, op_info_var.end_byte)
        index = get_text(src, index.start_byte, index.end_byte)
        return b"MCOperandInfo_isPredicate(&" + op_info_var + index + b")"

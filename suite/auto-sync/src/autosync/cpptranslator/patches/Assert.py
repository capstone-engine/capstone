# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Patch import Patch


class Assert(Patch):
    """
    Patch   Remove asserts
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(expression_statement"
            "   (call_expression"
            '       ((identifier) @id (#eq? @id "assert"))'
            "       (argument_list)"
            "   )"
            ") @assert"
        )

    def get_main_capture_name(self) -> str:
        return "assert"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        return b""

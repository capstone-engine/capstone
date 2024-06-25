# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch
from autosync.cpptranslator.patches.Helper import get_text_from_node


class Assert(Patch):
    """
    Patch   replace `assert`|`report_fatal_error` with `CS_ASSERT`
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(expression_statement"
            "   (call_expression"
            '       ((identifier) @id (#match? @id "assert|report_fatal_error"))'
            "       ((argument_list) @arg_list)"
            "   )"
            ") @assert"
        )

    def get_main_capture_name(self) -> str:
        return "assert"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        args = get_text_from_node(src, captures[2][0])
        return b"CS_ASSERT" + args + b";"

# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class CheckDecoderStatus(Patch):
    """
    Patch  "Check(S, ..."
    to     "Check(&S, ..."
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(call_expression"
            '    ((identifier) @fcn_name (#eq? @fcn_name "Check"))'
            "    ((argument_list) @arg_list)"
            ") @check_call"
        )

    def get_main_capture_name(self) -> str:
        return "check_call"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        call_expr: Node = captures[0][0]
        first_arg: Node = captures[2][0].named_children[0]

        call_text = get_text(src, call_expr.start_byte, call_expr.end_byte)
        first_arg_text = get_text(src, first_arg.start_byte, first_arg.end_byte)

        return call_text.replace(first_arg_text + b",", b"&" + first_arg_text + b",")

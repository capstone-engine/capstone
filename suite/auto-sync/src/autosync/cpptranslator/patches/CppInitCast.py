# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class CppInitCast(Patch):
    """
    Patch   int(...)
    to      (int)(...)
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(call_expression"
            "    (primitive_type) @cast_type"
            "    (argument_list) @cast_target"
            ") @cast"
        )

    def get_main_capture_name(self) -> str:
        return "cast"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        cast_type: Node = captures[1][0]
        cast_target: Node = captures[2][0]

        ctype = get_text(src, cast_type.start_byte, cast_type.end_byte)
        ctarget = get_text(src, cast_target.start_byte, cast_target.end_byte)
        return b"((" + ctype + b")" + ctarget + b")"

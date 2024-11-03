# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch
from autosync.cpptranslator.TemplateCollector import TemplateCollector


class IsUInt(Patch):
    """
    Patch   isUInt|isInt<N>(...)
    to      isUInt|isInt(..., N)
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(call_expression"
            "    (template_function"
            '         ((identifier) @id (#match? @id "isUInt|isInt"))'
            "         ((template_argument_list) @templ_args)"
            "    )"
            "    ((argument_list) @arg_list)"
            ") @is_u_int"
        )

    def get_main_capture_name(self) -> str:
        return "is_u_int"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        identifier: Node = captures[1][0]
        templ_args: Node = captures[2][0]
        args_list: Node = captures[3][0]

        name = get_text(src, identifier.start_byte, identifier.end_byte)
        targs = get_text(src, templ_args.start_byte, templ_args.end_byte).strip(b"<>")
        args = get_text(src, args_list.start_byte, args_list.end_byte).strip(b"()")

        res = name + b"N(" + targs + b", " + args + b")"

        return res

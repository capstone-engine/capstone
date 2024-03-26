# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class MethodTypeQualifier(Patch):
    """
    Patch   Removes type qualifiers like "const" etc. from methods.
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(function_declarator"
            "    (["
            "        (qualified_identifier)"
            "        (identifier)"
            "    ]) @id"
            "    (parameter_list) @param_list"
            "    (type_qualifier)"
            ")"
            "@method_type_qualifier"
        )

    def get_main_capture_name(self) -> str:
        return "method_type_qualifier"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        identifier = captures[1][0]
        parameter_list = captures[2][0]
        identifier = get_text(src, identifier.start_byte, identifier.end_byte)
        p_list = get_text(src, parameter_list.start_byte, parameter_list.end_byte)
        res = identifier + p_list
        return res

# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_capture_node, get_text
from autosync.cpptranslator.patches.Patch import Patch


class RegClassContains(Patch):
    """
    Patch   ...getRegClass(...).contains(Reg)
    to      MCRegisterClass_contains(...getRegClass(...), Reg)
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        q = (
            "(call_expression"
            "    (field_expression"
            '        ((_) @reg_class (#match? @reg_class ".+getRegClass.+"))'
            '        ((field_identifier) @field_id (#eq? @field_id "contains"))'
            "    )"
            "    ((argument_list) @arg_list)"
            ") @reg_class_contains"
        )
        return q

    def get_main_capture_name(self) -> str:
        return "reg_class_contains"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        reg_class_getter: Node = get_capture_node(captures, "reg_class")
        arg_list: Node = get_capture_node(captures, "arg_list")
        args = get_text(src, arg_list.start_byte, arg_list.end_byte).strip(b"()")
        reg_class = get_text(
            src, reg_class_getter.start_byte, reg_class_getter.end_byte
        )
        res = b"MCRegisterClass_contains(" + reg_class + b", " + args + b")"
        return res

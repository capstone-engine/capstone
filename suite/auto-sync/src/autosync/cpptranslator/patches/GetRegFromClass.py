# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_capture_node, get_text
from autosync.cpptranslator.patches.Patch import Patch


class GetRegFromClass(Patch):
    """
    Patch   <ARCH>MCRegisterClasses[<ARCH>::FPR128RegClassID].getRegister(RegNo);
    to      <ARCH>MCRegisterClasses[<ARCH>::FPR128RegClassID].RegsBegin[RegNo];
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        q = (
            "(call_expression"
            "    (field_expression"
            '        ((_) @operand (#match? @operand ".+MCRegisterClasses.*"))'
            '        ((field_identifier) @field_id (#eq? @field_id "getRegister"))'
            "    )"
            "    (argument_list) @arg_list"
            ") @get_reg_from_class"
        )
        return q

    def get_main_capture_name(self) -> str:
        return "get_reg_from_class"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        # Table
        table: Node = get_capture_node(captures, "operand")
        # args
        getter_args = get_capture_node(captures, "arg_list")

        tbl = get_text(src, table.start_byte, table.end_byte)
        args = get_text(src, getter_args.start_byte, getter_args.end_byte)

        res = tbl + b".RegsBegin" + args.replace(b"(", b"[").replace(b")", b"]")
        return res

# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class SetOpcode(Patch):
    """
    Patch   Inst.setOpcode(...)
    to      MCInst_setOpcode(Inst, ...)
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(call_expression"
            "    (field_expression ("
            "        ((identifier) @inst_var)"
            '        ((field_identifier) @field_id (#eq? @field_id "setOpcode")))'
            "     )"
            "    (argument_list) @arg_list"
            ") @set_opcode"
        )

    def get_main_capture_name(self) -> str:
        return "set_opcode"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        # Instruction variable
        inst_var: Node = captures[1][0]
        arg_list: Node = captures[3][0]

        inst = get_text(src, inst_var.start_byte, inst_var.end_byte)
        args = get_text(src, arg_list.start_byte, arg_list.end_byte)
        if args != b"()":
            args = b", " + args
        else:
            args = b""
        return b"MCInst_setOpcode(" + inst + args + b")"

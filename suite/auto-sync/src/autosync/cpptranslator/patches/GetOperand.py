# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class GetOperand(Patch):
    """
    Patch   MI.getOperand(...)
    to      MCInst_getOperand(MI, ...)
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        q = (
            "(call_expression "
            "   (field_expression"
            "       ((identifier) @inst_var)"
            '       ((field_identifier) @field_id_op (#eq? @field_id_op "getOperand"))'
            "   )"
            "   ((argument_list) @arg_list)"
            ") @get_operand"
        )
        return q

    def get_main_capture_name(self) -> str:
        return "get_operand"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        # Get instruction variable name (MI, Inst)
        inst_var: Node = captures[1][0]
        # Arguments of getOperand(...)
        get_op_args = captures[3][0]
        inst = get_text(src, inst_var.start_byte, inst_var.end_byte)
        args = get_text(src, get_op_args.start_byte, get_op_args.end_byte)
        return b"MCInst_getOperand(" + inst + b", " + args + b")"

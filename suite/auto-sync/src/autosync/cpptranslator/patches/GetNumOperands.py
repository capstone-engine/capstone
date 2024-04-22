# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class GetNumOperands(Patch):
    """
    Patch   MI.getNumOperands()
    to      MCInst_getNumOperands(MI)
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        q = (
            "(call_expression "
            "   (field_expression"
            "       ((identifier) @inst_var)"
            '       ((field_identifier) @field_id_op (#eq? @field_id_op "getNumOperands"))'
            "   )"
            "   ((argument_list) @arg_list)"
            ") @get_num_operands"
        )
        return q

    def get_main_capture_name(self) -> str:
        return "get_num_operands"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        # Get instruction variable name: MI, Inst etc.
        inst_var: Node = captures[1][0]
        inst = get_text(src, inst_var.start_byte, inst_var.end_byte)
        return b"MCInst_getNumOperands(" + inst + b")"

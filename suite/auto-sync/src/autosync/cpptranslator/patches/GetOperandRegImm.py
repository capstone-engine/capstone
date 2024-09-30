# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_capture_node, get_text
from autosync.cpptranslator.patches.Patch import Patch


class GetOperandRegImm(Patch):
    """
    Patch   OPERAND.getReg()
    to      MCOperand_getReg(OPERAND)

    Same for getImm()|getExpr
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        q = (
            "(call_expression"
            "    (field_expression"
            "        ((_) @operand)"
            '        ((field_identifier) @field_id (#match? @field_id "get(Reg|Imm|Expr)"))'
            "    )"
            '    ((argument_list) @arg_list (#eq? @arg_list "()"))'
            ") @get_operand"
        )
        return q

    def get_main_capture_name(self) -> str:
        return "get_operand"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        # The operand
        operand: Node = get_capture_node(captures, "operand")
        # 'getReg()/getImm()\getExpr'
        get_reg_imm = get_capture_node(captures, "field_id")

        fcn = get_text(src, get_reg_imm.start_byte, get_reg_imm.end_byte)
        op = get_text(src, operand.start_byte, operand.end_byte)
        return b"MCOperand_" + fcn + b"(" + op + b")"

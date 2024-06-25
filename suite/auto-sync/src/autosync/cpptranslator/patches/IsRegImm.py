# Copyright © 2022 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class IsOperandRegImm(Patch):
    """
    Patch   OPERAND.isReg()
    to      MCOperand_isReg(OPERAND)

    Same for isImm() | isExpr()
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        q = (
            "(call_expression"
            "    (field_expression"
            "        ((_) @operand)"
            '        ((field_identifier) @field_id (#match? @field_id "is(Reg|Imm|Expr)"))'
            "    )"
            "    (argument_list)"
            ") @is_operand"
        )
        return q

    def get_main_capture_name(self) -> str:
        return "is_operand"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        # The operand
        operand: Node = captures[1][0]
        # 'isReg()/isImm()/isExpr'
        get_reg_imm = captures[2][0]

        fcn = get_text(src, get_reg_imm.start_byte, get_reg_imm.end_byte)
        op = get_text(src, operand.start_byte, operand.end_byte)
        return b"MCOperand_" + fcn + b"(" + op + b")"

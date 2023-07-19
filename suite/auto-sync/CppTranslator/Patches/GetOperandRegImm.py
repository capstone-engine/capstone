import logging as log
import re

from tree_sitter import Node

from Patches.HelperMethods import get_text
from Patches.Patch import Patch


class GetOperandRegImm(Patch):
    """
    Patch   OPERAND.getReg()
    to      MCOperand_getReg(OPERAND)
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        q = (
            "(call_expression"
            "    (field_expression"
            "        ((_) @operand)"
            '        ((field_identifier) @field_id (#match? @field_id "get[RI][em][gm]"))'
            "    )"
            "    (argument_list)"
            ") @get_operand"
        )
        return q

    def get_main_capture_name(self) -> str:
        return "get_operand"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        # The operand
        operand: Node = captures[1][0]
        # 'getReg()/getImm()'
        get_reg_imm = captures[2][0]

        fcn = get_text(src, get_reg_imm.start_byte, get_reg_imm.end_byte)
        op = get_text(src, operand.start_byte, operand.end_byte)
        return b"MCOperand_" + fcn + b"(" + op + b")"

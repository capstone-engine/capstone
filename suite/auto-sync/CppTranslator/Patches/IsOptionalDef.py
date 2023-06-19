import logging as log
import re

from tree_sitter import Node

from Patches.HelperMethods import get_text
from Patches.Patch import Patch


class IsOptionalDef(Patch):
    """
    Patch   OpInfo[i].isPredicate()
    to      MCOperandInfo_isPredicate(&OpInfo[i])
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(call_expression"
            "   (field_expression"
            "       (subscript_expression"
            "           ((identifier) @op_info_var)"
            "           ((_) @index)"
            "       )"
            '       ((field_identifier) @fid (#eq? @fid "isOptionalDef"))'
            "   )"
            ") @is_optional_def"
        )

    def get_main_capture_name(self) -> str:
        return "is_optional_def"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        op_info_var = captures[1][0]
        index = captures[2][0]
        op_info_var = get_text(src, op_info_var.start_byte, op_info_var.end_byte)
        index = get_text(src, index.start_byte, index.end_byte)
        return b"MCOperandInfo_isOptionalDef(&" + op_info_var + b"[" + index + b"])"

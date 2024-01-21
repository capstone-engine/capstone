from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class Size(Patch):
    """
    Patch   Bytes.size()
    to      BytesLen
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        q = (
            "(call_expression "
            "   (field_expression"
            "       ((identifier) @inst_var)"
            '       ((field_identifier) @field_id_op (#eq? @field_id_op "size"))'
            "   )"
            "   ((argument_list) @arg_list)"
            ") @size"
        )
        return q

    def get_main_capture_name(self) -> str:
        return "size"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        # Get operand variable name (Bytes, ArrayRef)
        op_var: Node = captures[1][0]
        op = get_text(src, op_var.start_byte, op_var.end_byte)
        return op + b"Len"

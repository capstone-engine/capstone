from tree_sitter import Node

from Patches.HelperMethods import get_text
from Patches.Patch import Patch


class AArch64GetRegFromClass(Patch):
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
            ") @get_reg"
        )
        return q

    def get_main_capture_name(self) -> str:
        return "get_reg"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        # Table
        table: Node = captures[1][0]
        # args
        getter_args = captures[3][0]

        tbl = get_text(src, table.start_byte, table.end_byte)
        args = get_text(src, getter_args.start_byte, getter_args.end_byte)

        res = tbl + b".RegsBegin" + args.replace(b"(", b"[").replace(b")", b"]")
        return res

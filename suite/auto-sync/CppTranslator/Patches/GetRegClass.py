from tree_sitter import Node

from Patches.HelperMethods import get_text, get_capture_node, get_MCInst_var_name
from Patches.Patch import Patch


class GetRegClass(Patch):
    """
    Patch   MRI.getRegClass(...)
    to      MCRegisterClass_getRegClass(MI->MRI, ...)
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        q = (
            "(call_expression"
            "    (field_expression"
            "        (_)"
            '        ((field_identifier) @field_id (#eq? @field_id "getRegClass"))'
            "    )"
            "    ((argument_list) @arg_list)"
            ") @get_reg_class"
        )
        return q

    def get_main_capture_name(self) -> str:
        return "get_reg_class"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        arg_list: Node = get_capture_node(captures, "arg_list")
        args = get_text(src, arg_list.start_byte, arg_list.end_byte).strip(b"()")
        mcinst_var = get_MCInst_var_name(src, get_capture_node(captures, "get_reg_class"))
        res = b"MCRegisterClass_getRegClass(" + mcinst_var + b"->MRI, " + args + b")"
        return res

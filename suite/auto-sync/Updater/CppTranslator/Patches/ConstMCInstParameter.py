from tree_sitter import Node

from Patches.HelperMethods import get_text
from Patches.Patch import Patch


class ConstMCInstParameter(Patch):
    """
    Patch   const MCInst *MI
    to      MCInst *MI

    Removes the const qualifier from MCInst parameters because functions like MCInst_getOperand() ignore them anyway.
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return (
            "(parameter_declaration"
            "   ((type_qualifier) @type_qualifier)"
            '   ((type_identifier) @type_id (#eq? @type_id "MCInst"))'
            "   (pointer_declarator) @ptr_decl"
            ") @mcinst_param"
        )

    def get_main_capture_name(self) -> str:
        return "mcinst_param"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        inst = captures[3][0]
        inst = get_text(src, inst.start_byte, inst.end_byte)
        return b"MCInst " + inst

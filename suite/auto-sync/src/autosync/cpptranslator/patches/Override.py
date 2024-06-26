from tree_sitter import Node

from autosync.cpptranslator.patches.Helper import get_text
from autosync.cpptranslator.patches.Patch import Patch


class Override(Patch):
    """
    Patch   function(args) override
    to      function(args)
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        q = (
            "(function_declarator "
            "   ((field_identifier) @declarator)"
            "   ((parameter_list) @parameter_list)"
            '   ((virtual_specifier) @specifier (#eq? @specifier "override"))'
            ") @override"
        )
        return q

    def get_main_capture_name(self) -> str:
        return "override"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        # Get function name
        declarator: Node = captures[1][0]
        # Get parameter list
        parameter_list: Node = captures[2][0]
        decl = get_text(src, declarator.start_byte, declarator.end_byte)
        params = get_text(src, parameter_list.start_byte, parameter_list.end_byte)
        return decl + params

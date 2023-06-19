from tree_sitter import Node
from Patches.Patch import Patch


class ClassConstructorDef(Patch):
    """
    Removes Class constructor definitions with a field initializer list.
    Removes Class::Class(...) : ... {}
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        q = (
            "(function_definition"
            "   (function_declarator)"
            "   (field_initializer_list)"
            "   (compound_statement)"
            ") @class_constructor"
        )
        return q

    def get_main_capture_name(self) -> str:
        return "class_constructor"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        return b""

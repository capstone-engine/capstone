from tree_sitter import Node

from Patches.Patch import Patch


class UsingDeclaration(Patch):
    """
    Patch   Removes declarations with the keyword "using"
    """

    def __init__(self, priority: int):
        super().__init__(priority)

    def get_search_pattern(self) -> str:
        return "([(using_declaration) (alias_declaration)]) @using_declaration"

    def get_main_capture_name(self) -> str:
        return "using_declaration"

    def get_patch(self, captures: [(Node, str)], src: bytes, **kwargs) -> bytes:
        return b""
